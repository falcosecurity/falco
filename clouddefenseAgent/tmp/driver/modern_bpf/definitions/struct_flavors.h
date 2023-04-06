/* We need this header to keep track of all struct/field/enum changes between kernel versions */

#ifndef __STRUCT_FLAVORS_H__
#define __STRUCT_FLAVORS_H__

#include "vmlinux.h"

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
#endif

struct mm_struct___v6_2
{
	struct percpu_counter rss_stat[NR_MM_COUNTERS];
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __STRUCT_FLAVORS_H__ */
