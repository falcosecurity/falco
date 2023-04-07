/*

Copyright (C) 2022 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef FEATURE_GATES_H
#define FEATURE_GATES_H

/* FEATURE GATES:
 * 
 * These feature gates are used by: 
 * - kernel module
 * - BPF probe
 * - userspace
 * - modern BPF probe
 * to compile out some features. The userspace is in charge of 
 * filling the BPF maps that's why it also needs these macros.
 * 
 * This file is included by the 2 drivers and the userspace so 
 * it could be the right place to define these feature gates.
 */


#ifdef __KERNEL__ /* Kernel module - BPF probe */

#include "ppm_version.h"

///////////////////////////////
// CAPTURE_SCHED_PROC_FORK 
///////////////////////////////

/* In some architectures we are not able to catch the `clone exit child
 * event` from the `sys_exit` tracepoint. This is because there is no 
 * default behavior among different architectures... you can find more 
 * info here: 
 * https://www.spinics.net/lists/linux-trace/msg01001.html
 * 
 * Anyway, to not lose this event, we need to instrument a new kernel tracepoint:
 * 
 * - `sched_process_fork`: allows us to catch every new process that is spawned.
 * 
 * In this way we can detect when a child is spawned and we can send to userspace
 * a `PPME_SYSCALL_CLONE_X` event as we do with the `sys_exit` tracepoint.
 * 
 * Please note: in BPF we need to use raw_tracepoint programs to access
 * the raw tracepoint arguments! This is essential for `sched_process_fork`
 * tracepoint since the only way we have to access the child task struct 
 * is through its raw arguments. All the architectures that need this 
 * patch can use our BPF probe only with kernel versions greater or equal 
 * than `4.17`, since `BPF_PROG_TYPE_RAW_TRACEPOINT` programs have been 
 * introduced in this kernel release:
 * https://github.com/torvalds/linux/commit/c4f6699dfcb8558d138fe838f741b2c10f416cf9
 * 
 * If you run old kernels, you can use the kernel module which requires 
 * kernel versions greater or equal than `2.6`, since this tracepoint has
 * been introduced in the following kernel release:
 * https://github.com/torvalds/linux/commit/0a16b6075843325dc402edf80c1662838b929aff
 */
#if defined(CONFIG_ARM64) || defined(CONFIG_S390)
	#define CAPTURE_SCHED_PROC_FORK 
#endif

///////////////////////////////
// CAPTURE_SOCKETCALL
///////////////////////////////

/* There are architectures that used history socketcall to multiplex
 * the network system calls.  Even if architectures, like s390x, has
 * direct support for those network system calls, kernel version header
 * dependencies in libc prevent using them.
 *
 * For details, see also https://sourceware.org/pipermail/libc-alpha/2022-September/142108.html
 */
#if defined(CONFIG_S390)
	#define CAPTURE_SOCKETCALL
#endif

///////////////////////////////
// CAPTURE_SCHED_PROC_EXEC 
///////////////////////////////

/* In some architectures we are not able to catch the `execve exit event` 
 * from the `sys_exit` tracepoint. This is because there is no 
 * default behavior among different architectures... you can find more 
 * info here: 
 * https://www.spinics.net/lists/linux-trace/msg01001.html
 * 
 * Anyway, to not lose this event, we need to instrument a new kernel tracepoint:
 * 
 * - `sched_process_exec`: allows us to catch every process that correctly performs
 *                         an `execve` call.
 * 
 * In this way we can send to userspace a `PPME_SYSCALL_EXECVE_X` event
 * as we do with the `sys_exit` tracepoint.
 * 
 * All the architectures that need this patch can use our BPF probe with all 
 * supported kernel versions (so >= `4.14`), since `BPF_PROG_TYPE_RAW_TRACEPOINT` are
 * not required in this case.
 * 
 * If you run old kernels, you can use the kernel module which requires 
 * kernel versions greater or equal than `3.4`, since this tracepoint has
 * been introduced in the following kernel release:
 * https://github.com/torvalds/linux/commit/4ff16c25e2cc48cbe6956e356c38a25ac063a64d
 */
#if defined(CONFIG_ARM64)
	#define CAPTURE_SCHED_PROC_EXEC 
#endif

///////////////////////////////
// CAPTURE_64BIT_ARGS_SINGLE_REGISTER 
///////////////////////////////

/* This is described in syscall(2). Some syscalls take 64-bit arguments. On
 * arches that have 64-bit registers, these arguments are shipped in a register.
 * On 32-bit arches, however, these are split between two consecutive registers,
 * with some alignment requirements. Some require an odd/even pair while some
 * others require even/odd. For now, I assume they all do what x86_32 does, and
 * we can handle the rest when we port those.
 */
#ifdef CONFIG_64BIT
	#define CAPTURE_64BIT_ARGS_SINGLE_REGISTER
#endif /* CONFIG_64BIT */

///////////////////////////////
// CAPTURE_CONTEXT_SWITCHES 
///////////////////////////////

#define CAPTURE_CONTEXT_SWITCHES

///////////////////////////////
// CAPTURE_SIGNAL_DELIVERIES 
///////////////////////////////

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32))
	#define CAPTURE_SIGNAL_DELIVERIES
#endif

///////////////////////////////
// CAPTURE_PAGE_FAULTS 
///////////////////////////////

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 12, 0)) && defined(CONFIG_X86)
	#define CAPTURE_PAGE_FAULTS
#endif

///////////////////////////////
// USE_BPF_PROBE_KERNEL_USER_VARIANTS
///////////////////////////////

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)) || \
	((PPM_RHEL_RELEASE_CODE > 0) && (PPM_RHEL_RELEASE_CODE >= PPM_RHEL_RELEASE_VERSION(8, 5)))
		#define USE_BPF_PROBE_KERNEL_USER_VARIANTS
#endif

#elif defined(__USE_VMLINUX__) /* modern BPF probe */

///////////////////////////////
// CAPTURE_SCHED_PROC_EXEC 
///////////////////////////////

#if defined(__TARGET_ARCH_arm64)
	#define CAPTURE_SCHED_PROC_EXEC 
#endif

///////////////////////////////
// CAPTURE_SCHED_PROC_FORK 
///////////////////////////////

#if defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_s390)
	#define CAPTURE_SCHED_PROC_FORK 
#endif

///////////////////////////////
// CAPTURE_PAGE_FAULTS
///////////////////////////////

#if defined(__TARGET_ARCH_x86)
	#define CAPTURE_PAGE_FAULTS 
#endif

///////////////////////////////
// CAPTURE_SOCKETCALL
///////////////////////////////

#if defined(__TARGET_ARCH_s390)
	#define CAPTURE_SOCKETCALL
#endif

#else /* Userspace */

/* Please note: the userspace loads the filler table for the bpf probe
 * so it must define these macro according to what BPF supports
 */
#ifndef UDIG

///////////////////////////////
// CAPTURE_64BIT_ARGS_SINGLE_REGISTER 
///////////////////////////////

#if defined(__x86_64__) || defined(__aarch64__)
	#define CAPTURE_64BIT_ARGS_SINGLE_REGISTER
#endif 

///////////////////////////////
// CAPTURE_CONTEXT_SWITCHES 
///////////////////////////////

#define CAPTURE_CONTEXT_SWITCHES

///////////////////////////////
// CAPTURE_SIGNAL_DELIVERIES 
///////////////////////////////

#define CAPTURE_SIGNAL_DELIVERIES

///////////////////////////////
// CAPTURE_PAGE_FAULTS 
///////////////////////////////

#ifdef __x86_64__
	#define CAPTURE_PAGE_FAULTS
#endif /* __x86_64__ */

///////////////////////////////
// CAPTURE_SCHED_PROC_FORK 
///////////////////////////////

#if defined(__aarch64__) || defined(__s390x__)
	#define CAPTURE_SCHED_PROC_FORK 
#endif

///////////////////////////////
// CAPTURE_SCHED_PROC_EXEC 
///////////////////////////////

#if defined(__aarch64__)
	#define CAPTURE_SCHED_PROC_EXEC 
#endif

///////////////////////////////
// CAPTURE_SOCKETCALL
///////////////////////////////

#if defined(__s390x__)
	#define CAPTURE_SOCKETCALL
#endif

#endif /* UDIG */

#endif /* __KERNEL__ */

#endif /* FEATURE_GATES_H */
