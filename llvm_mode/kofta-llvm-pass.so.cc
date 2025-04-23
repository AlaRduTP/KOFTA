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
        ofs << option.first << ' ' << option.second << "\n";
      }
    }

    void addOption(const std::string &name, int hasArg) {
      options.emplace_back(name, hasArg);
    }

    size_t size() const {
      return options.size();
    }

  private:
    unsigned int map_id;

    // < option name, has_arg >
    std::vector<std::pair<std::string, int>> options;
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

    ConstantInt *ModuleID;

    FunctionCallee FuncModuleCov;
    FunctionCallee moduleCovProto(Module &M);

    FunctionCallee FuncModuleCovRet;
    FunctionCallee moduleCovRetProto(Module &M);

    void initVars(Module &M);

    size_t extractOptions(Instruction *Inst, std::ofstream &kofta_opts);

    void parseOptString(Value *OptString, OptionsMap &options);
    void parseLongOpt(Value *LongOpt, OptionsMap &options);
    void parseStrcmp(Value *OptString, OptionsMap &options);

    void logRet(Instruction *Inst);
    void logFunc(Function *F);
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

void KOFTAAnalysis::initVars(Module &M) {

  LLVMContext &C = M.getContext();

  VoidTy = Type::getVoidTy(C);

  Int8Ty = Type::getInt8Ty(C);
  Int16Ty = Type::getInt16Ty(C);
  Int32Ty = Type::getInt32Ty(C);
  Int64Ty = Type::getInt64Ty(C);

  ModuleID = ConstantInt::get(Int16Ty, R(MAP_SIZE));

  FuncModuleCov = moduleCovProto(M);
  FuncModuleCovRet = moduleCovRetProto(M);

}

size_t KOFTAAnalysis::extractOptions(Instruction *Inst, std::ofstream &kofta_opts) {

  CallInst *CI = dyn_cast<CallInst>(Inst);
  Function *CalledFunc = CI->getCalledFunction();
  if (!CalledFunc) return 0;

  unsigned int called_func_id = R(MAP_SIZE);
  OptionsMap options(called_func_id);

  // Check if this call is to 'getopt'
  if (CalledFunc->getName() == "getopt") {
    // getopt has the prototype: int getopt(int argc, char * const argv[], const char *optstring)
    // so the third argument (index 2) is the options string.
    Value *OptString = CI->getArgOperand(2);
    parseOptString(OptString, options);
  }
  // Check if this call is to 'getopt_long'
  else if (CalledFunc->getName() == "getopt_long") {
    Value *OptString = CI->getArgOperand(2);
    parseOptString(OptString, options);
    Value *LongOpt = CI->getArgOperand(3);
    parseLongOpt(LongOpt, options);
  }
  // Check if this call is to 'strcmp'
  else if (CalledFunc->getName() == "strcmp") {
    parseStrcmp(CI->getArgOperand(0), options);
    parseStrcmp(CI->getArgOperand(1), options);
  }

  options.dump(kofta_opts);
  return options.size();
}

void KOFTAAnalysis::parseOptString(Value *OptString, OptionsMap &options) {
  if(auto *LI = dyn_cast<LoadInst>(OptString)) {
    if (LI->getType()->isPointerTy()) {
      Value *Ptr = LI->getPointerOperand();
      if (auto *GV = dyn_cast<GlobalVariable>(Ptr)) {
        if (GV->hasInitializer()) {
          OptString = GV->getInitializer();
        }
      }
    }
  }
  
  StringRef OptStr;

  // Check if it's a constant expression (often a getelementptr).
  if (auto *CE = dyn_cast<ConstantExpr>(OptString)) {
    if (CE->getOpcode() == Instruction::GetElementPtr) {
      if (GlobalVariable *GV = dyn_cast<GlobalVariable>(CE->getOperand(0))) {
        if (GV->hasInitializer())
          if (ConstantDataArray *CDA = dyn_cast<ConstantDataArray>(GV->getInitializer()))
            OptStr = CDA->getAsCString();
      }
    }
  }

  if (!OptStr.empty()) {
    // Parse the options string...
    for (unsigned i = 0, n = OptStr.size(); i < n; ++i) {
      char optChar = OptStr[i];
      if (optChar == ':')
        continue;
      bool requiredArg = (i + 1) < n && OptStr[i + 1] == ':';
      bool optionalArg = requiredArg && (i + 2) < n && OptStr[i + 2] == ':';
      options.addOption("-" + std::string{optChar}, optionalArg ? 2 : (requiredArg ? 1 : 0));
    }
  }
}

void KOFTAAnalysis::parseLongOpt(Value *LongOpt, OptionsMap &options) {
  if (auto *CE = dyn_cast<ConstantExpr>(LongOpt)) {
    if (CE->getOpcode() == Instruction::GetElementPtr) {
      if (GlobalVariable *GV = dyn_cast<GlobalVariable>(CE->getOperand(0))) {
        if (GV->hasInitializer())
          if (ConstantArray *CA = dyn_cast<ConstantArray>(GV->getInitializer())) {
            for (unsigned i = 0, e = CA->getNumOperands(); i < e; ++i) {
              Constant *Elem = CA->getOperand(i);
              // Each element should be a struct (an instance of struct option)
              if (auto *CS = dyn_cast<ConstantStruct>(Elem)) {
                // The first field of the struct is the option name.
                Constant *NameField = CS->getOperand(0);
                // Stop if the option name is null (the sentinel element)
                if (NameField->isNullValue())
                  break;
                // The option name is typically stored as a pointer to a global constant string.
                if (auto *NameGV = dyn_cast<GlobalVariable>(NameField->stripPointerCasts())) {
                  if (GV->hasInitializer())
                    if (ConstantDataArray *CDA = dyn_cast<ConstantDataArray>(NameGV->getInitializer())) {
                      std::string option_long = "--" + CDA->getAsCString().str();
                      std::string option_short;
                      Constant *ShortField = CS->getOperand(3);
                      if (auto *ShortInt = dyn_cast<ConstantInt>(ShortField)) {
                        char short_value = ShortInt->getSExtValue();
                        if (isalpha(short_value)) {
                          option_short.push_back('-');
                          option_short.push_back(short_value);
                        }
                      }
                      int has_arg_value;
                      Constant *HasArgField = CS->getOperand(1);
                      if (auto *HasArgInt = dyn_cast<ConstantInt>(HasArgField)) {
                        has_arg_value = HasArgInt->getSExtValue();
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
            StringRef CString = CDA->getAsCString();
            if (CString.size() > 1 && CString.startswith("-")) {
              opt_str = CString.str();
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

static void registerAFLPass(const PassManagerBuilder &, legacy::PassManagerBase &PM) {
  PM.add(new KOFTAAnalysis());
}


static RegisterStandardPasses RegisterAFLPass(
  PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
  PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
