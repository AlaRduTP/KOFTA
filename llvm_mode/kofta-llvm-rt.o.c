#define _GNU_SOURCE

#include "kofta-llvm-rt.o.h"

#include "../config.h"
#include "../types.h"
#include "../alloc-inl.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/shm.h>

#define MAX_MODULE_DEPTH 255

static u8  module_depth;
static u16 module_stack[MAX_MODULE_DEPTH + 1][2];

static struct kofta_shm* kofta_shm;
static struct kofta_mcov* kofta_mcov;
static struct kofta_args* kofta_args;
static struct kofta_optana* kofta_optana;

static int* __argc_ptr;
static char*** __argv_ptr;

static arglist* kofta_arglist;
static u64 kofta_arglist_size;

static void __kofta_map_shm(void) {

  u8 *id_str = getenv(KOFTA_SHM_ENV_VAR);

  if (id_str) {

    u32 shm_id = atoi(id_str);
    kofta_shm = shmat(shm_id, NULL, 0);
    if (kofta_shm == (void *)-1) _exit(1);

    kofta_mcov = &kofta_shm->module_cov;
    kofta_mcov->trace_bits[0] = 'K';

    kofta_args = &kofta_shm->args;
    kofta_optana = &kofta_shm->optana;

  }
  else do { /* No fuzzer is running. */ } while(0);

}

static void __kofta_init_args(void) {

  kofta_arglist_size = KOFTA_ARGV_SIZE * (kofta_args->argcnt + KOFTA_OPTCNT_MAX);
  kofta_arglist = mmap(NULL, kofta_arglist_size, PROT_NONE, MAP_NORESERVE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

}

void __kofta_manual_init(void) {

  static u8 init_done;
  if (!init_done) {
    init_done = 1;
    __kofta_map_shm();
    if (!kofta_shm) return;
    __kofta_init_args();
  }

}

static void __kofta_module_cov_reset(void) {

  module_depth = 0;
  module_stack[module_depth][0] = 0;

}

void __kofta_module_cov(u16 cur_module) {

  u16 prev_module = module_stack[module_depth][0];

  if (!kofta_shm || module_depth == MAX_MODULE_DEPTH) return;

  if (prev_module == cur_module) {
    ++module_stack[module_depth][1];
    return;
  }

  module_depth += 1;
  module_stack[module_depth][0] = cur_module;
  module_stack[module_depth][1] = 1;

  u8* cur_bits = kofta_mcov->trace_bits + cur_module;

  if (!*cur_bits) {
    kofta_mcov->unique_hits += 1;
    *cur_bits = module_depth;
  }
  else if (module_depth < *cur_bits) {
    *cur_bits = module_depth;
  }

}

void __kofta_module_cov_ret(u16 cur_module) {

  if (!kofta_shm || module_depth == MAX_MODULE_DEPTH) return;

  if (!--module_stack[module_depth][1]) {
    --module_depth;
  }

}

static void __kofta_opt_analysis_reset(void) {

  if (!kofta_shm) return;
  kofta_optana->idcnt = 0;

}

void __kofta_opt_analysis(u16 optid) {

  if (!kofta_shm || kofta_optana->idcnt == KOFTA_OPTANA_MAX) return;

  kofta_optana->optid[kofta_optana->idcnt++] = optid;

}

void __kofta_update_opts(void) {

  static u32 prev_optcnt = 0xff;

  if (!kofta_shm || !kofta_args->changed) return;
  kofta_args->changed = 0;

  *__argc_ptr = kofta_args->argcnt + kofta_args->optcnt;

  kofta_arglist = mmap(kofta_arglist, kofta_arglist_size,
                       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, kofta_args->memfd, 0);

  if (prev_optcnt == kofta_args->optcnt) return;
  prev_optcnt = kofta_args->optcnt;

  (*__argv_ptr)[0] = kofta_arglist[0];
  for (u32 i = 0; i < kofta_args->optcnt; i++) {
    (*__argv_ptr)[i + 1] = kofta_arglist[kofta_args->argcnt + i];
  }
  for (u32 i = 1; i < kofta_args->argcnt; i++) {
    (*__argv_ptr)[i + kofta_args->optcnt] = kofta_arglist[i];
  }
  (*__argv_ptr)[kofta_args->argcnt + kofta_args->optcnt] = NULL;

}

void __kofta_shm_reset(void) {

  if (!kofta_shm) return;

  __kofta_module_cov_reset();
  __kofta_opt_analysis_reset();

}

/* Some dirty tricks. */

__attribute__((constructor(KOFTA_ARGSLEAK_PRIO))) static void __args_leak(void) {

  asm volatile(
    "lea 0x50(%%rsp), %0"
    : "=r" (__argv_ptr)
  );
  __argc_ptr = (int *)((unsigned long)__argv_ptr + 0xc);

}