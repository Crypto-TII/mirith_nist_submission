#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#if defined (OFFLINE_CC)
uint64_t offline_cc;
uint64_t begin_offline;
#endif

int cmp(const void *arg1, const void *arg2)
{
	uint64_t v1, v2;

	v1 = *(const uint64_t *)arg1;
	v2 = *(const uint64_t *)arg2;
	if (v1 < v2) {
		return -1;
	} else if (v1 == v2) {
		return 0;
	} else {
		return 1;
	}
}

double average(const uint64_t *cc, const uint64_t n_bench)
{
    int i;
    uint64_t acc = 0;

    for (i = 0; i < n_bench; i++)
    {
        acc += cc[i];
    }

    return (double)acc / n_bench;
}
