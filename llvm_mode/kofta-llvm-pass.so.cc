#define KOFTA_OPT_ANALYSIS_PASS

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "../config.h"
#include "../debug.h"

#include <unistd.h>

#include <cctype>
#include <fstream>
#include <map>
#include <string>
#include <utility>
#include <vector>

using namespace llvm;

namespace {

  class OptionsMap {

  public:
    OptionsMap(unsigned int map_id) : map_id(map_id) { }
    ~OptionsMap() = default;

    void dump(std::ofstream &ofs) const {
      if (!ofs || size() == 0) {
        return;
      }
      ofs << map_id << ' ' << size() << "\n";
      for (const auto &option : options) {
        ofs << option.second << ' ' << option.first << "\n";
      }
    }

    void addOption(const std::string &name, int hasArg) {
      if (options.count(name)) return;
      options[name] = hasArg;
    }

    size_t size() const {
      return options.size();
    }

  private:
    unsigned int map_id;

    // < option name, has_arg >
    std::map<std::string, int> options;
  };

  class KOFTAAnalysis : public ModulePass {

  public:

    static char ID;
    KOFTAAnalysis() : ModulePass(ID) { }

    bool runOnModule(Module &M) override;

  private:

    Type *VoidTy;

    IntegerType *Int8Ty;
    IntegerType *Int16Ty;
    IntegerType *Int32Ty;
    IntegerType *Int64Ty;

    PointerType *Int8PtrTy;

    ConstantInt *CnstNegOne;

    ConstantInt *ModuleID;

    FunctionCallee FuncModuleCov;
    FunctionCallee moduleCovProto(Module &M);

    FunctionCallee FuncModuleCovRet;
    FunctionCallee moduleCovRetProto(Module &M);

    FunctionCallee FuncOptAnalysis;
    FunctionCallee optAnalysisProto(Module &M);

    FunctionCallee FuncTraceStr;
    FunctionCallee traceStrProto(Module &M);

    void initVars(Module &M);

    size_t extractOptions(Instruction *Inst, std::ofstream &kofta_opts);

    void parseOpts(CallInst *CI, OptionsMap &options);
    void parseStrcmp(Value *OptString, OptionsMap &options);

    void logRet(Instruction *Inst);
    void logFunc(Function *F);

    void sanitizerCovTraceString(CallInst *CI, Value *Str1, Value *Str2, Value *Len = nullptr);
  };

} // end anonymous namespace

char KOFTAAnalysis::ID = 0;

bool KOFTAAnalysis::runOnModule(Module &M) {

  if (isatty(2) && !getenv("AFL_QUIET")) {
    SAYF(cCYA "kofta-llvm-pass " cBRI KOFTA_VERSION cRST " by <me@alardutp.dev>\n");
  }

  initVars(M);

  char *kofta_opt_save = getenv("KOFTA_OPTSAVE");
  if (!kofta_opt_save) {
    FATAL("Please set KOFTA_OPTSAVE.");
  }
  size_t opt_count = 0;
  std::ofstream kofta_opts;
  kofta_opts.open(kofta_opt_save, std::ios_base::app);

  for (Function &F : M) {
    if (F.hasExactDefinition()) {
      logFunc(&F);
    }
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if      (isa<CallInst>(&I))   opt_count += extractOptions(&I, kofta_opts);
        else if (isa<ReturnInst>(&I)) logRet(&I);
      }
    }
  }

  kofta_opts.close();
  if (opt_count) {
    OKF("Found %zu options. See %s.", opt_count, kofta_opt_save);
  }

  // This pass modifies the program.
  return true;

}

FunctionCallee KOFTAAnalysis::moduleCovProto(Module &M) {

  FunctionType *FT =
      FunctionType::get(VoidTy, { Int16Ty }, false);
  FunctionCallee FC = M.getOrInsertFunction("__kofta_module_cov", FT);

  return FC;

}

FunctionCallee KOFTAAnalysis::moduleCovRetProto(Module &M) {

  FunctionType *FT =
      FunctionType::get(VoidTy, { Int16Ty }, false);
  FunctionCallee FC = M.getOrInsertFunction("__kofta_module_cov_ret", FT);

  return FC;

}

FunctionCallee KOFTAAnalysis::optAnalysisProto(Module &M) {

  FunctionType *FT =
      FunctionType::get(VoidTy, { Int16Ty }, false);
  FunctionCallee FC = M.getOrInsertFunction("__kofta_opt_analysis", FT);

  return FC;

}

FunctionCallee KOFTAAnalysis::traceStrProto(Module &M) {

  FunctionType *FT =
      FunctionType::get(VoidTy, { Int8PtrTy, Int8PtrTy, Int64Ty }, false);
  FunctionCallee FC = M.getOrInsertFunction("__kofta_trace_str", FT);

  return FC;

}

void KOFTAAnalysis::initVars(Module &M) {

  LLVMContext &C = M.getContext();

  VoidTy = Type::getVoidTy(C);

  Int8Ty = Type::getInt8Ty(C);
  Int16Ty = Type::getInt16Ty(C);
  Int32Ty = Type::getInt32Ty(C);
  Int64Ty = Type::getInt64Ty(C);

  Int8PtrTy = Type::getInt8PtrTy(C);

  CnstNegOne = ConstantInt::get(Int64Ty, -1);

  ModuleID = ConstantInt::get(Int16Ty, R(MAP_SIZE));

  FuncModuleCov = moduleCovProto(M);
  FuncModuleCovRet = moduleCovRetProto(M);

  FuncOptAnalysis = optAnalysisProto(M);

  FuncTraceStr = traceStrProto(M);

}

size_t KOFTAAnalysis::extractOptions(Instruction *Inst, std::ofstream &kofta_opts) {

  CallInst *CI = dyn_cast<CallInst>(Inst);
  Function *CalledFunc = CI->getCalledFunction();
  if (!CalledFunc) return 0;

  unsigned int called_func_id = R(MAP_SIZE);
  OptionsMap options(called_func_id);

  // // Check if this call is to '*getopt*'
  if (CalledFunc->getName().contains("getopt")) {
    parseOpts(CI, options);
  }
  // Check if this call is to 'strcmp'
  else if (CalledFunc->getName() == "strcmp" || CalledFunc->getName() == "strcasecmp") {
    parseStrcmp(CI->getArgOperand(0), options);
    parseStrcmp(CI->getArgOperand(1), options);
    sanitizerCovTraceString(CI, CI->getArgOperand(0), CI->getArgOperand(1));
  }
  else if (CalledFunc->getName() == "strncmp" || CalledFunc->getName() == "strncasecmp" || CalledFunc->getName() == "memcmp") {
    parseStrcmp(CI->getArgOperand(0), options);
    parseStrcmp(CI->getArgOperand(1), options);
    sanitizerCovTraceString(CI, CI->getArgOperand(0), CI->getArgOperand(1), CI->getArgOperand(2));
  }

  if (options.size()) {
    IRBuilder<> IRB(Inst);
    ConstantInt *CalledFuncID = ConstantInt::get(Int16Ty, called_func_id);
    IRB.CreateCall(FuncOptAnalysis, { CalledFuncID });
  }

  options.dump(kofta_opts);
  return options.size();

}

void KOFTAAnalysis::parseOpts(CallInst *CI, OptionsMap &options) {

  for (unsigned i = 0, e = CI->getNumArgOperands(); i < e; ++i) {

    Value *Arg = CI->getArgOperand(i);

    if (LoadInst *LI = dyn_cast<LoadInst>(Arg)) {
      if (!LI->getPointerOperandType()->isPointerTy()) continue;
      GlobalVariable *GV = dyn_cast<GlobalVariable>(LI->getPointerOperand());
      if (!GV || !GV->hasInitializer()) continue;
      Arg = GV->getInitializer();
    }

    ConstantExpr *CE = dyn_cast<ConstantExpr>(Arg);
    if (!CE || CE->getOpcode() != Instruction::GetElementPtr) continue;
    GlobalVariable *GV = dyn_cast<GlobalVariable>(CE->getOperand(0));
    if (!GV || !GV->hasInitializer()) continue;

    Arg = GV->getInitializer();

    if (ConstantDataArray *CDA = dyn_cast<ConstantDataArray>(Arg)) {

      StringRef OptStr = CDA->getAsCString();
      if (OptStr.empty()) continue;

      for (unsigned j = 0, n = OptStr.size(); j < n; ++j) {
        char optChar = OptStr[j];
        if (optChar == ':')
          continue;
        bool requiredArg = (j + 1) < n && OptStr[j + 1] == ':';
        bool optionalArg = requiredArg && (j + 2) < n && OptStr[j + 2] == ':';
        options.addOption("-" + std::string{optChar}, optionalArg ? 2 : (requiredArg ? 1 : 0));
      }

    }
    else if (ConstantArray *CA = dyn_cast<ConstantArray>(Arg)) {

      for (unsigned j = 0, n = CA->getNumOperands(); j < n; ++j) {

        Constant *Elem = CA->getOperand(j);
        ConstantStruct *OptLong = dyn_cast<ConstantStruct>(Elem);
        if (!OptLong) continue;

        GlobalVariable *GV = dyn_cast<GlobalVariable>(OptLong->getOperand(0)->stripPointerCasts());
        if (!GV || !GV->hasInitializer()) continue;
        ConstantDataArray *NameField = dyn_cast<ConstantDataArray>(GV->getInitializer());
        if (!NameField || !NameField->isCString()) continue;

        std::string option_long = NameField->getAsCString().str();
        std::string option_short;
        int has_arg_value = 2;

        size_t pos = option_long.find_first_not_of('-');
        if (pos) option_long.erase(0, pos);
        pos = option_long.find_first_of('=');
        if (pos != std::string::npos) {
          option_long.erase(pos);
          has_arg_value = 1;
        }
        option_long.insert(0, "--");

        if (OptLong->getNumOperands() == 4) {
          Constant *ShortField = OptLong->getOperand(3);
          if (auto *ShortInt = dyn_cast<ConstantInt>(ShortField)) {
            char short_value = ShortInt->getSExtValue();
            if (isalpha(short_value)) {
              option_short.push_back('-');
              option_short.push_back(short_value);
            }
          }
          Constant *HasArgField = OptLong->getOperand(1);
          if (auto *HasArgInt = dyn_cast<ConstantInt>(HasArgField)) {
            has_arg_value = HasArgInt->getSExtValue();
          }
        }

        if (!option_short.empty()) {
          options.addOption(option_short, has_arg_value);
        } else {
          options.addOption(option_long, has_arg_value);
        }

      }

    }

  }

}

void KOFTAAnalysis::parseStrcmp(Value *OptString, OptionsMap &options) {
  std::string opt_str;

  if (auto *CE = dyn_cast<ConstantExpr>(OptString)) {
    if (CE->getOpcode() == Instruction::GetElementPtr) {
      if (GlobalVariable *GV = dyn_cast<GlobalVariable>(CE->getOperand(0))) {
        if (GV->hasInitializer())
          if (ConstantDataArray *CDA = dyn_cast<ConstantDataArray>(GV->getInitializer())) {
            if (CDA->isCString()) {
              StringRef CString = CDA->getAsCString();
              if (CString.size() > 1 && CString.startswith("-")) {
                opt_str = CString.str();
              }
            }
          }
      }
    }
  }

  if (!opt_str.empty()) {
    options.addOption(opt_str, 2);
  }
}

void KOFTAAnalysis::logFunc(Function *F) {

  Instruction *Inst = &F->getEntryBlock().front();
  IRBuilder<> IRB(Inst);
  IRB.CreateCall(FuncModuleCov, { ModuleID });

}

void KOFTAAnalysis::logRet(Instruction *Inst) {

  IRBuilder<> IRB(Inst);
  IRB.CreateCall(FuncModuleCovRet, { ModuleID });

}

void KOFTAAnalysis::sanitizerCovTraceString(CallInst *CI, Value *Str1, Value *Str2, Value *Len) {

  Value *Argv = Str1;
  Value *Cnst = Str2;

  if (Len == nullptr) Len = CnstNegOne;

  if (dyn_cast<ConstantExpr>(Str1)) {
    if (dyn_cast<ConstantExpr>(Str2)) return; // Both arguments are constant expressions.
    Cnst = Str1;
    Argv = Str2;
  }

  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(Cnst)) {
    if (CE->getOpcode() == Instruction::GetElementPtr) {
      if (GlobalVariable *GV = dyn_cast<GlobalVariable>(CE->getOperand(0))) {
        if (GV->hasInitializer())
          if (ConstantDataArray *CDA = dyn_cast<ConstantDataArray>(GV->getInitializer())) {
            if (!CDA->isCString()) return; // Not a C-style string.
            StringRef CString = CDA->getAsCString();
            if (CString.startswith("-")) return; // Skip if the string starts with a dash.
          }
      }
    }
  }

  IRBuilder<> IRB(CI);
  IRB.CreateCall(FuncTraceStr, { Cnst, Argv, Len });

}

static void registerAFLPass(const PassManagerBuilder &, legacy::PassManagerBase &PM) {
  PM.add(new KOFTAAnalysis());
}


static RegisterStandardPasses RegisterAFLPass(
  PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
  PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
