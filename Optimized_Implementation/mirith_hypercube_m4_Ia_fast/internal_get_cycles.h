#ifndef INTERNAL_GET_CYCLES_H
#define INTERNAL_GET_CYCLES_H

#include <inttypes.h>

#if defined (OFFLINE_CC)
extern uint64_t offline_cc;
extern uint64_t begin_offline;
#endif

#if !defined(__APPLE__) && !defined(__x86_64__)
#include "stm32f4xx_hal.h"
uint32_t _get_cycles(void);
uint32_t get_cycles(void) {
	return DWT->CYCCNT;
}
#else
uint64_t get_cycles(void) {
    /*
     * GCC seems not to have the __rdtsc() intrinsic.
     */
#if defined __GNUC__ && !defined __clang__
    uint32_t hi, lo;

	_mm_lfence();
	__asm__ __volatile__ ("rdtsc" : "=d" (hi), "=a" (lo) : : );
	return ((uint64_t)hi << 32) | (uint64_t)lo;
#else
    return __rdtsc();
#endif
}
#endif

double average(const uint64_t *cc, const uint64_t n_bench);
int cmp(const void *arg1, const void *arg2);

#endif
