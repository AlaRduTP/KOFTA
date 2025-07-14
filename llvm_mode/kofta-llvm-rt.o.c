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


static struct kofta_shm* kofta_shm;
static struct kofta_args* kofta_args;
static struct kofta_optana* kofta_optana;
static struct kofta_tntana* kofta_tntana;


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

    kofta_args = &kofta_shm->args;
    kofta_optana = &kofta_shm->optana;
    kofta_tntana = &kofta_shm->tntana;

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


static inline void __kofta_opt_analysis_reset(void) {

  kofta_optana->idcnt = 0;

}


void __kofta_opt_analysis(u16 optid) {

  if (unlikely(!kofta_shm || kofta_optana->idcnt == KOFTA_OPTANA_MAX)) return;

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

  u32 prefix_cnt = kofta_args->precnt;

  for (u32 i = 0; i < prefix_cnt; i++) {
    (*__argv_ptr)[i] = kofta_arglist[i];
  }
  for (u32 i = 0; i < kofta_args->optcnt; i++) {
    (*__argv_ptr)[i + prefix_cnt] = kofta_arglist[kofta_args->argcnt + i];
  }
  for (u32 i = prefix_cnt; i < kofta_args->argcnt; i++) {
    (*__argv_ptr)[i + kofta_args->optcnt] = kofta_arglist[i];
  }
  (*__argv_ptr)[kofta_args->argcnt + kofta_args->optcnt] = NULL;

}


static void __kofta_taint_may_set_hint(void* src, u8 type, u32 tntidx) {

  if (kofta_tntana->hint_cnt == KOFTA_HINTS_MAX) return;

  u32 hint_idx = kofta_tntana->hint_cnt++;
  union kofta_tntdat* dest = &kofta_tntana->hints[hint_idx];

  kofta_tntana->types[hint_idx] = type;

  switch (type) {

  case KOFTA_TRACE_CMP: {

    dest->num = *(u64*)src;
    break;

  }

  case KOFTA_TRACE_SWT: {

    dest->num = ((u64*)src)[R(((u64*)src)[0]) + 2];
    break;

  }

  case KOFTA_TRACE_STR: {

    strncpy(dest->str, (u8*)src, KOFTA_ARGV_SIZE - 1);
    dest->str[KOFTA_ARGV_SIZE - 1] = '\0';
    break;

  }

  }

}


static void __kofta_taint_analysis(u8 type, u8 hash, void* data) {

  static u32 tntidx = 0;
  static u8  chara = 0;
  static u8  anastate = 0;

  switch (kofta_tntana->mode) {

  case KOFTA_TNTANA_MODE_SETUP: {

    if (unlikely(kofta_tntana->trace_cnt == MAP_SIZE)) return;

    kofta_tntana->trace_hash[kofta_tntana->trace_cnt++] = hash;

    return;

  }

  case KOFTA_TNTANA_MODE_COMPR: {

    if (unlikely(tntidx == kofta_tntana->trace_cnt)) return;

    if (likely(kofta_tntana->trace_hash[tntidx++] == hash)) return;

    chara = hash & 0xf;
    kofta_tntana->found = tntidx;

    kofta_tntana->mode = KOFTA_TNTANA_MODE_FOUND;
    __kofta_taint_may_set_hint(data, type, tntidx);

    return;

  }

  case KOFTA_TNTANA_MODE_FOUND: {

    if (unlikely(tntidx == kofta_tntana->trace_cnt)) return;

    switch (anastate) {

    case 0: {

      if (chara != (hash & 0xf))
        anastate = 1;
      else
        __kofta_taint_may_set_hint(data, type, tntidx);
      break;

    }

    case 1: {

      if (kofta_tntana->trace_hash[tntidx] == hash)
        anastate = 2;
      break;

    }

    case 2: {

      if (kofta_tntana->trace_hash[tntidx] == hash) break;

      chara = hash & 0xf;

      anastate = 0;
      __kofta_taint_may_set_hint(data, type, tntidx);

    }

    }

    ++tntidx;

    return;

  }

  }

}


static inline void __kofta_taint_analysis_reset(void) {

  if (unlikely(kofta_tntana->mode == KOFTA_TNTANA_MODE_SETUP)) {

    kofta_tntana->trace_cnt = 0;
    kofta_tntana->found = 0;

  };

  if (unlikely(kofta_tntana->mode == KOFTA_TNTANA_MODE_COMPR)) {

    kofta_tntana->hint_cnt = 0;

  }

}


static inline void __kofta_trace_cmp(u8 size, u64 cnst, u64 argv) {

  if (likely(!cnst || !kofta_shm || kofta_tntana->mode == KOFTA_TNTANA_MODE_NOP)) return;

  u8 chara = size ^ (argv & 0xff);
  u8 hash = ((chara * cnst) << 4) | (chara & 0xf);

  __kofta_taint_analysis(KOFTA_TRACE_CMP, hash, &cnst);

}


static inline void __kofta_trace_swt(u8 size, u64* cases, u64 argv) {

  if (likely(!kofta_shm || kofta_tntana->mode == KOFTA_TNTANA_MODE_NOP)) return;

  u8 chara = size ^ (argv & 0xff);
  u8 cnt = cases[0];

  u8 hash = chara * cnt;
  for (u8 i = 0; i < cnt; i++) {
    hash = (hash << 1) * cases[i + 2];
  }
  hash = (hash << 4) | (chara & 0xf);

  __kofta_taint_analysis(KOFTA_TRACE_SWT, hash, cases);

}


static inline u8 __kofta_hash_str(const u8* str, s64 len) {

  if (len < 0)
    while (str[++len]);

  u8 hash = 0;
  while (*str && len--) {
    hash = (hash << 1) ^ *str;
    ++str;
  }
  return hash;

}


void __kofta_trace_str(u8* cnst, u8* argv, s64 len) {

  if (likely(!kofta_shm || kofta_tntana->mode == KOFTA_TNTANA_MODE_NOP)) return;

  u8 chara = __kofta_hash_str(argv, len);
  u8 hash = ((chara * __kofta_hash_str(cnst, len)) << 4) | (chara & 0xf);

  __kofta_taint_analysis(KOFTA_TRACE_STR, hash, cnst);

}


void __kofta_shm_reset(void) {

  if (unlikely(!kofta_shm)) return;

  srandom(random());

  __kofta_opt_analysis_reset();
  __kofta_taint_analysis_reset();

}


/* Some dirty tricks. */

__attribute__((constructor(KOFTA_ARGSLEAK_PRIO))) static void __args_leak(void) {

  asm volatile(
    "lea 0x50(%%rsp), %0"
    : "=r" (__argv_ptr)
  );
  __argc_ptr = (int *)((unsigned long)__argv_ptr + 0xc);

}


/* LLVM SanitizerCoverage - Tracing data flow.
   See, https://releases.llvm.org/10.0.0/tools/clang/docs/SanitizerCoverage.html#tracing-data-flow */


void __sanitizer_cov_trace_const_cmp1(u8 cnst, u8 argv) {
  __kofta_trace_cmp(1, cnst, argv);
}


void __sanitizer_cov_trace_const_cmp2(u16 cnst, u16 argv) {
  __kofta_trace_cmp(2, cnst, argv);
}


void __sanitizer_cov_trace_const_cmp4(u32 cnst, u32 argv) {
  __kofta_trace_cmp(4, cnst, argv);
}


void __sanitizer_cov_trace_const_cmp8(u64 cnst, u64 argv) {
  __kofta_trace_cmp(8, cnst, argv);
}


void __sanitizer_cov_trace_switch(u64 argv, u64* cases) {
  __kofta_trace_swt(cases[1] / 8, cases, argv);
}