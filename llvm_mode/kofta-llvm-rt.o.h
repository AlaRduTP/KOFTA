#ifndef KOFTA_LLVM_RT
#define KOFTA_LLVM_RT

#define KOFTA_ARGSLEAK_PRIO 101
#define KOFTA_FORKSRV_PRIO  102

#define KOFTA_ARGV_SIZE     128
#define KOFTA_OPTCNT_MAX      8
#define KOFTA_OPTANA_MAX     32

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

struct kofta_shm {
  struct kofta_mcov module_cov;
  struct kofta_args args;
  struct kofta_optana optana;
};

void __kofta_shm_reset(void);

void __kofta_manual_init(void);
void __kofta_update_opts(void);

#endif /* !KOFTA_LLVM_RT */