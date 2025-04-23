#include "kofta-llvm-rt.o.h"

#include "../config.h"
#include "../types.h"
#include "../alloc-inl.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/shm.h>

#define MAX_MODULE_DEPTH 255

static u8  module_depth;
static u16 module_stack[MAX_MODULE_DEPTH + 1][2];

static struct kofta_shm* kofta_shm;
static struct kofta_mcov* kofta_mcov;

static void __kofta_map_shm(void) {
  
  u8 *id_str = getenv(KOFTA_SHM_ENV_VAR);

  if (id_str) {

    u32 shm_id = atoi(id_str);
    kofta_shm = shmat(shm_id, NULL, 0);
    if (kofta_shm == (void *)-1) _exit(1);
    
    kofta_mcov = &kofta_shm->module_cov;
    kofta_mcov->trace_bits[0] = 'K';

  }
  else do { /* No fuzzer is running. */ } while(0);

}

void __kofta_manual_init(void) {

  static u8 init_done;
  if (!init_done) {
    __kofta_map_shm();
    init_done = 1;
  }

}

void __kofta_module_cov_reset(void) {

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