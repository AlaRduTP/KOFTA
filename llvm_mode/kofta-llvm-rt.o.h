#ifndef KOFTA_LLVM_RT
#define KOFTA_LLVM_RT

#include "../config.h"
#include "../types.h"

struct kofta_mcov {
  u32 unique_hits;
  u8  trace_bits[MAP_SIZE];
};

struct kofta_shm {
  struct kofta_mcov module_cov;
};

void __kofta_module_cov_reset(void);
void __kofta_manual_init(void);

#endif /* !KOFTA_LLVM_RT */