/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef PPM_FILLERS_H_
#define PPM_FILLERS_H_

#define FILLER_LIST_MAPPER(FN)			\
	FN(sys_autofill)			\
	FN(sys_generic)				\
	FN(sys_empty)				\
	FN(sys_single)				\
	FN(sys_single_x)			\
	FN(sys_open_e)				\
	FN(sys_open_x)				\
	FN(sys_read_e)				\
	FN(sys_read_x)				\
	FN(sys_write_e)				\
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
	FN(sys_creat_e)				\
	FN(sys_creat_x)				\
	FN(sys_pipe_x)				\
	FN(sys_eventfd_e)			\
	FN(sys_futex_e)				\
	FN(sys_lseek_e)				\
	FN(sys_llseek_e)			\
	FN(sys_socket_bind_x)			\
	FN(sys_poll_e)				\
	FN(sys_poll_x)				\
	FN(sys_pread_e)			\
	FN(sys_writev_e)			\
	FN(sys_pwrite64_e)			\
	FN(sys_readv_e)				\
	FN(sys_preadv_e)			\
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
	FN(sys_renameat2_x)			\
	FN(sys_symlinkat_x)			\
	FN(sys_procexit_e)			\
	FN(sys_sendfile_e)			\
	FN(sys_sendfile_x)			\
	FN(sys_quotactl_e)			\
	FN(sys_quotactl_x)			\
	FN(sys_scapevent_e)			\
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
        FN(sys_chown_x)				\
	FN(sys_lchown_x)			\
	FN(sys_fchown_x)			\
	FN(sys_fchownat_x)			\
	FN(sys_mkdirat_x)			\
	FN(sys_openat_e)			\
	FN(sys_openat_x)			\
	FN(sys_openat2_e)			\
	FN(sys_openat2_x)			\
	FN(sys_linkat_x)			\
	FN(sys_mprotect_e)			\
	FN(sys_mprotect_x)			\
	FN(sys_execveat_e)			\
	FN(execve_family_flags)		\
	FN(sys_copy_file_range_e)	\
	FN(sys_copy_file_range_x)	\
	FN(sys_connect_e)			\
	FN(sys_open_by_handle_at_x) \
	FN(sys_io_uring_setup_x)		\
	FN(sys_io_uring_enter_x)		\
	FN(sys_io_uring_register_x)		\
	FN(sys_mlock_x)                 	\
	FN(sys_munlock_x)              		\
	FN(sys_mlockall_x)			\
	FN(sys_munlockall_x)			\
	FN(sys_capset_x)			\
	FN(sys_dup2_e)				\
	FN(sys_dup2_x)				\
	FN(sys_dup3_e)				\
	FN(sys_dup3_x)				\
	FN(sys_dup_e)				\
	FN(sys_dup_x)				\
	FN(sched_prog_exec)			\
	FN(sched_prog_exec_2)		        \
	FN(sched_prog_exec_3)		        \
	FN(sched_prog_exec_4)		        \
	FN(sched_prog_fork)			\
	FN(sched_prog_fork_2)		        \
	FN(sched_prog_fork_3)		        \
	FN(sys_mlock2_x)			\
	FN(sys_fsconfig_x)			\
	FN(sys_epoll_create_e)                  \
	FN(sys_epoll_create_x)                  \
	FN(sys_epoll_create1_e)                 \
	FN(sys_epoll_create1_x)                 \
	FN(sys_socket_bind_e)                 \
	FN(sys_bpf_e)                 \
	FN(sys_close_e)                 \
	FN(sys_close_x)                 \
	FN(sys_fchdir_e)                 \
	FN(sys_fchdir_x)                 \
	FN(sys_ioctl_e)                 \
	FN(sys_mkdir_e)                 \
	FN(sys_setpgid_e)                 \
	FN(sys_recvfrom_e)                 \
	FN(sys_recvmsg_e)                 \
	FN(sys_signalfd_e)                 \
	FN(sys_splice_e)				\
	FN(sys_umount_x)				\
	FN(sys_umount2_e)				\
	FN(sys_umount2_x)				\
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
