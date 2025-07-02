#ifndef KOFTA_LLVM_RT
#define KOFTA_LLVM_RT


#define KOFTA_ARGSLEAK_PRIO 101
#define KOFTA_FORKSRV_PRIO  102


#define KOFTA_ARGV_SIZE     128
#define KOFTA_OPTCNT_MAX      8
#define KOFTA_OPTANA_MAX     32


#define KOFTA_TNTANA_MODE_NOP    0
#define KOFTA_TNTANA_MODE_SETUP  1
#define KOFTA_TNTANA_MODE_COMPR  2
#define KOFTA_TNTANA_MODE_FOUND  3


#define KOFTA_TRACE_CMP 'K'
#define KOFTA_TRACE_SWT 'O'
#define KOFTA_TRACE_STR 'F'


#define KOFTA_HINTS_MAX (MAP_SIZE / KOFTA_ARGV_SIZE)


#include "../config.h"
#include "../types.h"


typedef u8 arglist[KOFTA_ARGV_SIZE];


struct kofta_mcov {
  u32 unique_hits;
  u8  trace_bits[MAP_SIZE];
};


struct kofta_args {
  u8  changed;
  u32 memfd;
  u32 argcnt;
  u32 optcnt;
};


struct kofta_optana {
  u8  idcnt;
  u16 optid[KOFTA_OPTANA_MAX];
};


union kofta_tntdat {
  u8  str[KOFTA_ARGV_SIZE];
  u64 num;
};


struct kofta_tntana {
  u8  trace_hash[MAP_SIZE];
  u32 trace_cnt;
  u8  mode;
  u32 found;
  u32 hint_cnt;
  u8  types[KOFTA_HINTS_MAX];
  union kofta_tntdat hints[KOFTA_HINTS_MAX];
};


struct kofta_shm {
  struct kofta_mcov module_cov;
  struct kofta_args args;
  struct kofta_optana optana;
  struct kofta_tntana tntana;
};

void __kofta_shm_reset(void);


void __kofta_manual_init(void);
void __kofta_update_opts(void);


#endif /* !KOFTA_LLVM_RT */