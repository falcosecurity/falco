/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __QUIRKS_H
#define __QUIRKS_H

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#error Kernel version must be >= 4.14 with eBPF enabled
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 4)
#define randomized_struct_fields_start  struct {
#define randomized_struct_fields_end    };
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
#define BPF_FORBIDS_ZERO_ACCESS
#endif

#if (defined(CONFIG_X86_64) || defined(CONFIG_ARM64) || defined(CONFIG_S390)) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
    #define BPF_SUPPORTS_RAW_TRACEPOINTS
#endif

#if CAPTURE_SCHED_PROC_FORK && !defined(BPF_SUPPORTS_RAW_TRACEPOINTS)
    #error The CAPTURE_SCHED_PROC_FORK support requires 'raw_tracepoints' so kernel versions greater or equal than '4.17'.
#endif

/* Redefine asm_volatile_goto to work around clang not supporting it
 */
#include <linux/types.h>

#ifdef asm_volatile_goto
#undef asm_volatile_goto
#define asm_volatile_goto(...) asm volatile("invalid use of asm_volatile_goto")
#endif

/* Ditto for asm_inline (new in Linux 5.4)
 */
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#endif /* __QUIRKS_H */
