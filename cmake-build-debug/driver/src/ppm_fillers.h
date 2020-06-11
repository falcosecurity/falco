/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef PPM_FILLERS_H_
#define PPM_FILLERS_H_

/* This is described in syscall(2). Some syscalls take 64-bit arguments. On
 * arches that have 64-bit registers, these arguments are shipped in a register.
 * On 32-bit arches, however, these are split between two consecutive registers,
 * with some alignment requirements. Some require an odd/even pair while some
 * others require even/odd. For now I assume they all do what x86_32 does, and
 * we can handle the rest when we port those.
 */
#ifdef __KERNEL__
#ifdef CONFIG_64BIT
#define _64BIT_ARGS_SINGLE_REGISTER
#endif /* CONFIG_64BIT */
#else
#ifdef __x86_64__
#define _64BIT_ARGS_SINGLE_REGISTER
#endif /* __x86_64__ */
#endif /* __KERNEL__ */

#define FILLER_LIST_MAPPER(FN)			\
	FN(sys_autofill)			\
	FN(sys_generic)				\
	FN(sys_empty)				\
	FN(sys_single)				\
	FN(sys_single_x)			\
	FN(sys_open_x)				\
	FN(sys_read_x)				\
	FN(sys_write_x)				\
	FN(sys_execve_e)			\
	FN(proc_startupdate)			\
	FN(proc_startupdate_2)			\
	FN(proc_startupdate_3)			\
	FN(sys_socketpair_x)			\
	FN(sys_setsockopt_x)			\
	FN(sys_getsockopt_x)			\
	FN(sys_connect_x)			\
	FN(sys_accept4_e)			\
	FN(sys_accept_x)			\
	FN(sys_send_e)				\
	FN(sys_send_x)				\
	FN(sys_sendto_e)			\
	FN(sys_sendmsg_e)			\
	FN(sys_sendmsg_x)			\
	FN(sys_recv_x)				\
	FN(sys_recvfrom_x)			\
	FN(sys_recvmsg_x)			\
	FN(sys_recvmsg_x_2)			\
	FN(sys_shutdown_e)			\
	FN(sys_creat_x)				\
	FN(sys_pipe_x)				\
	FN(sys_eventfd_e)			\
	FN(sys_futex_e)				\
	FN(sys_lseek_e)				\
	FN(sys_llseek_e)			\
	FN(sys_socket_bind_x)			\
	FN(sys_poll_e)				\
	FN(sys_poll_x)				\
	FN(sys_pread64_e)			\
	FN(sys_preadv64_e)			\
	FN(sys_writev_e)			\
	FN(sys_pwrite64_e)			\
	FN(sys_readv_preadv_x)			\
	FN(sys_writev_pwritev_x)		\
	FN(sys_pwritev_e)			\
	FN(sys_nanosleep_e)			\
	FN(sys_getrlimit_setrlimit_e)		\
	FN(sys_getrlimit_setrlrimit_x)		\
	FN(sys_prlimit_e)			\
	FN(sys_prlimit_x)			\
	FN(sched_switch_e)			\
	FN(sched_drop)				\
	FN(sys_fcntl_e)				\
	FN(sys_ptrace_e)			\
	FN(sys_ptrace_x)			\
	FN(sys_mmap_e)				\
	FN(sys_brk_munmap_mmap_x)		\
	FN(sys_renameat_x)			\
	FN(sys_symlinkat_x)			\
	FN(sys_procexit_e)			\
	FN(sys_sendfile_e)			\
	FN(sys_sendfile_x)			\
	FN(sys_quotactl_e)			\
	FN(sys_quotactl_x)			\
	FN(sys_sysdigevent_e)			\
	FN(sys_getresuid_and_gid_x)		\
	FN(sys_signaldeliver_e)			\
	FN(sys_pagefault_e)			\
	FN(sys_setns_e)				\
	FN(sys_unshare_e)			\
	FN(sys_flock_e)				\
	FN(cpu_hotplug_e)			\
	FN(sys_semop_x)				\
	FN(sys_semget_e)			\
	FN(sys_semctl_e)			\
	FN(sys_ppoll_e)				\
	FN(sys_mount_e)				\
	FN(sys_access_e)			\
	FN(sys_socket_x)			\
	FN(sys_bpf_x)				\
	FN(sys_unlinkat_x)			\
	FN(sys_fchmodat_x)			\
	FN(sys_chmod_x)				\
	FN(sys_fchmod_x)			\
	FN(sys_mkdirat_x)			\
	FN(sys_openat_x)			\
	FN(sys_linkat_x)			\
	FN(terminate_filler)

#define FILLER_ENUM_FN(x) PPM_FILLER_##x,
enum ppm_filler_id {
	FILLER_LIST_MAPPER(FILLER_ENUM_FN)
	PPM_FILLER_MAX
};
#undef FILLER_ENUM_FN

#define FILLER_PROTOTYPE_FN(x) int f_##x(struct event_filler_arguments *args);
FILLER_LIST_MAPPER(FILLER_PROTOTYPE_FN)
#undef FILLER_PROTOTYPE_FN

#endif /* PPM_FILLERS_H_ */
