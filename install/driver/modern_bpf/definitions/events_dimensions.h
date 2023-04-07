/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#ifndef __EVENT_DIMENSIONS_H__
#define __EVENT_DIMENSIONS_H__

#include "vmlinux.h"

/* Here we have all the dimensions for fixed-size events.
 */

#define PARAM_LEN 2
#define HEADER_LEN sizeof(struct ppm_evt_hdr)

/// TODO: We have to move these in the event_table.c. Right now we don't
/// want to touch scap tables.

/* Syscall events */
#define GENERIC_E_SIZE HEADER_LEN + sizeof(uint16_t) * 2 + PARAM_LEN * 2
#define GENERIC_X_SIZE HEADER_LEN + sizeof(uint16_t) + PARAM_LEN
#define MKDIR_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define MMAP_E_SIZE HEADER_LEN + sizeof(uint64_t) * 3 + sizeof(int64_t) + sizeof(uint32_t) * 2 + PARAM_LEN * 6
#define MMAP_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 3 + PARAM_LEN * 4
#define MUNMAP_E_SIZE HEADER_LEN + sizeof(uint64_t) * 2 + PARAM_LEN * 2
#define MUNMAP_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 3 + PARAM_LEN * 4
#define OPEN_BY_HANDLE_AT_E_SIZE HEADER_LEN
#define CLOSE_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define CLOSE_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define COPY_FILE_RANGE_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) * 2 + PARAM_LEN * 3
#define COPY_FILE_RANGE_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint64_t) + PARAM_LEN * 3
#define DUP_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define DUP_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + PARAM_LEN * 2
#define DUP2_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define DUP2_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + PARAM_LEN * 3
#define DUP3_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define DUP3_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint32_t) + PARAM_LEN * 4
#define CHDIR_E_SIZE HEADER_LEN
#define CHMOD_E_SIZE HEADER_LEN
#define CHOWN_E_SIZE HEADER_LEN
#define LCHOWN_E_SIZE HEADER_LEN
#define CHROOT_E_SIZE HEADER_LEN
#define FCHDIR_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define FCHDIR_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define FCHMOD_E_SIZE HEADER_LEN
#define FCHMOD_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint32_t) + PARAM_LEN * 3
#define FCHMODAT_E_SIZE HEADER_LEN
#define FCHOWN_E_SIZE HEADER_LEN
#define FCHOWN_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint32_t) * 2 + PARAM_LEN * 4
#define FCHOWNAT_E_SIZE HEADER_LEN
#define MKDIRAT_E_SIZE HEADER_LEN
#define RMDIR_E_SIZE HEADER_LEN
#define EVENTFD_E_SIZE HEADER_LEN + sizeof(uint64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define EVENTFD_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define INOTIFY_INIT_E_SIZE HEADER_LEN + sizeof(uint8_t) + PARAM_LEN
#define INOTIFY_INIT_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define TIMERFD_CREATE_E_SIZE HEADER_LEN + sizeof(uint8_t) * 2 + PARAM_LEN * 2
#define TIMERFD_CREATE_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define USERFAULTFD_E_SIZE HEADER_LEN
#define USERFAULTFD_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define SIGNALFD_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + sizeof(uint8_t) + PARAM_LEN * 3
#define SIGNALFD_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define KILL_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint8_t) + PARAM_LEN * 2
#define KILL_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define TGKILL_E_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint8_t) + PARAM_LEN * 3
#define TGKILL_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define TKILL_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint8_t) + PARAM_LEN * 2
#define TKILL_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SECCOMP_E_SIZE HEADER_LEN + sizeof(uint64_t) + PARAM_LEN
#define SECCOMP_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define PTRACE_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint16_t) + PARAM_LEN * 2
#define CAPSET_E_SIZE HEADER_LEN
#define CAPSET_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) * 3 + PARAM_LEN * 4
#define SOCKET_E_SIZE HEADER_LEN + sizeof(uint32_t) * 3 + PARAM_LEN * 3
#define SOCKET_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SOCKETPAIR_E_SIZE HEADER_LEN + sizeof(uint32_t) * 3 + PARAM_LEN * 3
#define SOCKETPAIR_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint64_t) * 2 + PARAM_LEN * 5
#define ACCEPT_E_SIZE HEADER_LEN
#define ACCEPT4_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define BIND_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define LISTEN_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define LISTEN_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define CLONE_E_SIZE HEADER_LEN
#define CLONE3_E_SIZE HEADER_LEN
#define FORK_E_SIZE HEADER_LEN
#define VFORK_E_SIZE HEADER_LEN
#define RENAME_E_SIZE HEADER_LEN
#define RENAMEAT_E_SIZE HEADER_LEN
#define RENAMEAT2_E_SIZE HEADER_LEN
#define PIPE_E_SIZE HEADER_LEN
#define PIPE_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint64_t) + PARAM_LEN * 4
#define BPF_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define BPF_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define FLOCK_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define FLOCK_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define IOCTL_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) * 2 + PARAM_LEN * 3
#define IOCTL_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define QUOTACTL_E_SIZE HEADER_LEN + sizeof(uint16_t) + sizeof(uint8_t) * 2 + sizeof(uint32_t) + PARAM_LEN * 4
#define UNSHARE_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define UNSHARE_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define MOUNT_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define UMOUNT2_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define UMOUNT_E_SIZE HEADER_LEN
#define LINK_E_SIZE HEADER_LEN
#define LINKAT_E_SIZE HEADER_LEN
#define SYMLINK_E_SIZE HEADER_LEN
#define SYMLINKAT_E_SIZE HEADER_LEN
#define UNLINK_E_SIZE HEADER_LEN
#define UNLINKAT_E_SIZE HEADER_LEN
#define SETGID_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define SETGID_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SETUID_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define SETUID_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SETNS_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define SETNS_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SETPGID_E_SIZE HEADER_LEN + sizeof(int64_t) * 2 + PARAM_LEN * 2
#define SETPGID_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SETRESGID_E_SIZE HEADER_LEN + sizeof(uint32_t) * 3 + PARAM_LEN * 3
#define SETRESGID_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SETRESUID_E_SIZE HEADER_LEN + sizeof(uint32_t) * 3 + PARAM_LEN * 3
#define SETRESUID_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SETSID_E_SIZE HEADER_LEN
#define SETSID_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SETRLIMIT_E_SIZE HEADER_LEN + sizeof(uint8_t) + PARAM_LEN
#define SETRLIMIT_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + PARAM_LEN * 3
#define PRLIMIT64_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint8_t) + PARAM_LEN * 2
#define PRLIMIT64_X_SIZE HEADER_LEN + sizeof(int64_t) * 5 + PARAM_LEN * 5
#define GETSOCKOPT_E_SIZE HEADER_LEN
#define SETSOCKOPT_E_SIZE HEADER_LEN
#define RECVMSG_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define READV_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define PREADV_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) + PARAM_LEN * 2
#define PREAD_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + sizeof(uint64_t) + PARAM_LEN * 3
#define RECVFROM_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define FCNTL_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint8_t) + PARAM_LEN * 2
#define FCNTL_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SHUTDOWN_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint8_t) + PARAM_LEN * 2
#define SHUTDOWN_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define FSCONFIG_E_SIZE HEADER_LEN
#define EPOLL_CREATE_E_SIZE HEADER_LEN + sizeof(int32_t) + PARAM_LEN
#define EPOLL_CREATE_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define EPOLL_CREATE1_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define EPOLL_CREATE1_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define ACCESS_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define MPROTECT_E_SIZE HEADER_LEN + sizeof(uint64_t) * 2 + sizeof(uint32_t) + PARAM_LEN * 3
#define MPROTECT_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define GETUID_E_SIZE HEADER_LEN
#define GETUID_X_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define GETGID_E_SIZE HEADER_LEN
#define GETGID_X_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define GETEUID_E_SIZE HEADER_LEN
#define GETEUID_X_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define GETEGID_E_SIZE HEADER_LEN
#define GETEGID_X_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define MLOCK_E_SIZE HEADER_LEN
#define MLOCK_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) * 2 + PARAM_LEN * 3
#define MLOCK2_E_SIZE HEADER_LEN
#define MLOCK2_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + sizeof(uint64_t) * 2 + PARAM_LEN * 4
#define MUNLOCK_E_SIZE HEADER_LEN
#define MUNLOCK_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) * 2 + PARAM_LEN * 3
#define MLOCKALL_E_SIZE HEADER_LEN
#define MLOCKALL_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define MUNLOCKALL_E_SIZE HEADER_LEN
#define MUNLOCKALL_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define READ_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define IO_URING_ENTER_E_SIZE HEADER_LEN
#define IO_URING_ENTER_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint32_t) * 4 + PARAM_LEN * 6
#define IO_URING_REGISTER_E_SIZE HEADER_LEN
#define IO_URING_REGISTER_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint16_t) + sizeof(uint64_t) + sizeof(uint32_t) + PARAM_LEN * 5
#define IO_URING_SETUP_E_SIZE HEADER_LEN
#define IO_URING_SETUP_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 7 + PARAM_LEN * 8
#define MMAP2_E_SIZE HEADER_LEN + sizeof(uint64_t) * 3 + sizeof(int64_t) + sizeof(uint32_t) * 2 + PARAM_LEN * 6
#define MMAP2_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 3 + PARAM_LEN * 4
#define SEMGET_E_SIZE HEADER_LEN + sizeof(int32_t) * 2 + sizeof(uint32_t) + PARAM_LEN * 3
#define SEMGET_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN 
#define SEMCTL_E_SIZE HEADER_LEN + sizeof(int32_t) * 3 + sizeof(uint16_t) + PARAM_LEN * 4
#define SEMCTL_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SELECT_E_SIZE HEADER_LEN
#define SELECT_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SPLICE_E_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint64_t) + sizeof(uint32_t) + PARAM_LEN * 4
#define SPLICE_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define RECVMMSG_E_SIZE HEADER_LEN
#define RECVMMSG_X_SIZE HEADER_LEN
#define SENDMMSG_E_SIZE HEADER_LEN
#define SENDMMSG_X_SIZE HEADER_LEN
#define SEMOP_E_SIZE HEADER_LEN + sizeof(int32_t) + PARAM_LEN
#define SEMOP_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + sizeof(uint16_t) * 4 + sizeof(int16_t) * 2 + PARAM_LEN * 8
#define GETRESUID_E_SIZE HEADER_LEN
#define GETRESUID_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 3 + PARAM_LEN * 4
#define SENDFILE_E_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint64_t) * 2 + PARAM_LEN * 4
#define SENDFILE_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) + PARAM_LEN * 2
#define FUTEX_E_SIZE HEADER_LEN + sizeof(uint64_t) * 2 + sizeof(uint16_t) + PARAM_LEN * 3
#define FUTEX_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define STAT_E_SIZE HEADER_LEN
#define LSEEK_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) + sizeof(uint8_t) + 3 * PARAM_LEN 
#define LSEEK_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define LLSEEK_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) + sizeof(uint8_t) + 3 * PARAM_LEN 
#define LLSEEK_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define WRITE_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define GETRESGID_E_SIZE HEADER_LEN
#define GETRESGID_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 3 + PARAM_LEN * 4
#define BRK_E_SIZE HEADER_LEN + sizeof(uint64_t) + PARAM_LEN
#define BRK_X_SIZE HEADER_LEN + sizeof(uint64_t) + sizeof(uint32_t) * 3 + PARAM_LEN * 4
#define GETRLIMIT_E_SIZE HEADER_LEN + sizeof(uint8_t) + PARAM_LEN
#define GETRLIMIT_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + PARAM_LEN * 3
#define SEND_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define RECV_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define NANOSLEEP_E_SIZE HEADER_LEN + sizeof(uint64_t) + PARAM_LEN
#define NANOSLEEP_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN

/* Generic tracepoints events. */
#define PROC_EXIT_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint8_t) * 2 + PARAM_LEN * 4
#define SCHED_SWITCH_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) * 2 + sizeof(uint32_t) * 3 + PARAM_LEN * 6
#define PAGE_FAULT_SIZE HEADER_LEN + sizeof(uint64_t) * 2 + sizeof(uint32_t) + PARAM_LEN * 3
#define SIGNAL_DELIVER_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint8_t) + PARAM_LEN * 3

/* Special internal events */
#define DROP_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define DROP_X_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN

#endif /* __EVENT_DIMENSIONS_H__ */
