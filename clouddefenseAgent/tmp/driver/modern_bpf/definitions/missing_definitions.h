/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#ifndef __MISSING_DEFINITIONS_H__
#define __MISSING_DEFINITIONS_H__

/* This header should include different definitions according to different architectures.*/

/* PF_KTHREAD flag to mark the kernel threads */
#define PF_KTHREAD 0x00200000

/*=============================== ARCH SPECIFIC ===========================*/

#if defined(__TARGET_ARCH_x86)

/* 32bit syscall active (only in ARCH_x86) */
#define TS_COMPAT 0x0002

#elif defined(__TARGET_ARCH_arm64)

/* Taken from arch/arm64/include/asm/thread_info.h */
#define _TIF_32BIT (1 << 22)

#elif defined(__TARGET_ARCH_s390)

/* See here for definition:
 * https://github.com/torvalds/linux/blob/69cb6c6556ad89620547318439d6be8bb1629a5a/arch/s390/include/asm/thread_info.h#L101
 */
#define _TIF_31BIT (1 << 16)

#endif

/*=============================== ARCH SPECIFIC ===========================*/

/*=============================== SIGNALS ===========================*/

#define SI_QUEUE -1
#define SI_USER 0
#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGIOT 6
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGSTKFLT 16
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGURG 23
#define SIGXCPU 24
#define SIGXFSZ 25
#define SIGVTALRM 26
#define SIGPROF 27
#define SIGWINCH 28
#define SIGIO 29
#define SIGPOLL SIGIO
/*
#define SIGLOST		29
*/
#define SIGPWR 30
#define SIGSYS 31
#define SIGUNUSED 31
#define SIGRTMIN 32
#define __SIGRTMAX 64
#define _NSIG (__SIGRTMAX + 1)
#define SIGRTMAX _NSIG

/*=============================== SIGNALS ===========================*/

/*=============================== FLAGS ===========================*/

//////////////////////////
// cloning flags
//////////////////////////

/* `/include/uapi/linux/sched.h`  from kernel source tree. */

#define CSIGNAL 0x000000ff		/* signal mask to be sent at exit */
#define CLONE_VM 0x00000100		/* set if VM shared between processes */
#define CLONE_FS 0x00000200		/* set if fs info shared between processes */
#define CLONE_FILES 0x00000400		/* set if open files shared between processes */
#define CLONE_SIGHAND 0x00000800	/* set if signal handlers and blocked signals shared */
#define CLONE_PIDFD 0x00001000		/* set if a pidfd should be placed in parent */
#define CLONE_PTRACE 0x00002000		/* set if we want to let tracing continue on the child too */
#define CLONE_VFORK 0x00004000		/* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT 0x00008000		/* set if we want to have the same parent as the cloner */
#define CLONE_THREAD 0x00010000		/* Same thread group? */
#define CLONE_NEWNS 0x00020000		/* New mount namespace group */
#define CLONE_SYSVSEM 0x00040000	/* share system V SEM_UNDO semantics */
#define CLONE_SETTLS 0x00080000		/* create a new TLS for the child */
#define CLONE_PARENT_SETTID 0x00100000	/* set the TID in the parent */
#define CLONE_CHILD_CLEARTID 0x00200000 /* clear the TID in the child */
#define CLONE_DETACHED 0x00400000	/* Unused, ignored */
#define CLONE_UNTRACED 0x00800000	/* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID 0x01000000	/* set the TID in the child */
#define CLONE_NEWCGROUP 0x02000000	/* New cgroup namespace */
#define CLONE_NEWUTS 0x04000000		/* New utsname namespace */
#define CLONE_NEWIPC 0x08000000		/* New ipc namespace */
#define CLONE_NEWUSER 0x10000000	/* New user namespace */
#define CLONE_NEWPID 0x20000000		/* New pid namespace */
#define CLONE_NEWNET 0x40000000		/* New network namespace */
#define CLONE_IO 0x80000000		/* Clone io context */

/* Flags for the clone3() syscall. */
#define CLONE_CLEAR_SIGHAND 0x100000000ULL /* Clear any signal handler and reset to SIG_DFL. */
#define CLONE_INTO_CGROUP 0x200000000ULL   /* Clone into a specific cgroup given the right permissions. */

/*
 * cloning flags intersect with CSIGNAL so can be used with unshare and clone3
 * syscalls only:
 */
#define CLONE_NEWTIME 0x00000080 /* New time namespace */

//////////////////////////
// O_* bits
//////////////////////////

/* `/include/uapi/asm-generic/fnctl.h` from kernel source tree. */

#define O_ACCMODE 00000003
#define O_RDONLY 00000000
#define O_WRONLY 00000001
#define O_RDWR 00000002
#define O_CREAT 00000100  /* not fcntl */
#define O_EXCL 00000200	  /* not fcntl */
#define O_NOCTTY 00000400 /* not fcntl */
#define O_TRUNC 00001000  /* not fcntl */
#define O_APPEND 00002000
#define O_NONBLOCK 00004000
#define O_NDELAY O_NONBLOCK
#define O_DSYNC 00010000 /* used to be O_SYNC, see below */
#define FASYNC 00020000	 /* fcntl, for BSD compatibility */

#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_s390)

#define O_DIRECT 00040000 /* direct disk access hint */
#define O_LARGEFILE 00100000
#define O_DIRECTORY 00200000 /* must be a directory */
#define O_NOFOLLOW 00400000  /* don't follow links */

#elif defined(__TARGET_ARCH_arm64)

/* `/arch/arm64/include/uapi/asm/fcntl.h` from kernel source tree. */

#define O_DIRECTORY 040000 /* must be a directory */
#define O_NOFOLLOW 0100000 /* don't follow links */
#define O_DIRECT 0200000   /* direct disk access hint - currently ignored */
#define O_LARGEFILE 0400000

#endif

#define O_NOATIME 01000000
#define O_CLOEXEC 02000000 /* set close_on_exec */
#define __O_SYNC 04000000
#define O_SYNC (__O_SYNC | O_DSYNC)
#define O_PATH 010000000
#define __O_TMPFILE 020000000

/* a horrid kludge trying to make sure that this will fail on old kernels */
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#define O_TMPFILE_MASK (__O_TMPFILE | O_DIRECTORY | O_CREAT)

//////////////////////////
// openat2 flags
//////////////////////////

/* `/include/uapi/linux/openat2.h` from kernel source tree. */

/*
 * how->resolve flags for openat2(2).
 */
#define RESOLVE_NO_XDEV 0x01	   /* Block mount-point crossings (includes bind-mounts). */
#define RESOLVE_NO_MAGICLINKS 0x02 /* Block traversal through procfs-style "magic-links". */
#define RESOLVE_NO_SYMLINKS 0x04   /* Block traversal through all symlinks (implies OEXT_NO_MAGICLINKS) */
#define RESOLVE_BENEATH 0x08	   /* Block "lexical" trickery like "..", symlinks, and absolute paths which escape the dirfd. */
#define RESOLVE_IN_ROOT 0x10	   /* Make all jumps to "/" and ".." be scoped inside the dirfd (similar to chroot(2)). */
#define RESOLVE_CACHED 0x20	   /* Only complete if resolution can be completed through cached lookup. May return -EAGAIN if that's not possible. */

//////////////////////////
// io_uring flags
//////////////////////////

/* `/include/uapi/linux/io_uring.h` from kernel source tree. */

/*
 * Io_uring_setup flags
 */
#define IORING_SETUP_IOPOLL (1U << 0)	  /* io_context is polled */
#define IORING_SETUP_SQPOLL (1U << 1)	  /* SQ poll thread */
#define IORING_SETUP_SQ_AFF (1U << 2)	  /* sq_thread_cpu is valid */
#define IORING_SETUP_CQSIZE (1U << 3)	  /* app defines CQ size */
#define IORING_SETUP_CLAMP (1U << 4)	  /* clamp SQ/CQ ring sizes */
#define IORING_SETUP_ATTACH_WQ (1U << 5)  /* attach to existing wq */
#define IORING_SETUP_R_DISABLED (1U << 6) /* start with ring disabled */

/*
 * Io_uring_setup feats
 */
#define IORING_FEAT_SINGLE_MMAP (1U << 0)
#define IORING_FEAT_NODROP (1U << 1)
#define IORING_FEAT_SUBMIT_STABLE (1U << 2)
#define IORING_FEAT_RW_CUR_POS (1U << 3)
#define IORING_FEAT_CUR_PERSONALITY (1U << 4)
#define IORING_FEAT_FAST_POLL (1U << 5)
#define IORING_FEAT_POLL_32BITS (1U << 6)
#define IORING_FEAT_SQPOLL_NONFIXED (1U << 7)
#define IORING_FEAT_EXT_ARG (1U << 8)
#define IORING_FEAT_NATIVE_WORKERS (1U << 9)
#define IORING_FEAT_RSRC_TAGS (1U << 10)
#define IORING_FEAT_CQE_SKIP (1U << 11)

/*
 * Io_uring_enter flags
 */
#define IORING_ENTER_GETEVENTS (1U << 0)
#define IORING_ENTER_SQ_WAKEUP (1U << 1)
#define IORING_ENTER_SQ_WAIT (1U << 2)
#define IORING_ENTER_EXT_ARG (1U << 3)

/*
 * sq_ring->flags
 */
#define IORING_SQ_NEED_WAKEUP (1U << 0) /* needs io_uring_enter wakeup */
#define IORING_SQ_CQ_OVERFLOW (1U << 1) /* CQ ring is overflown */

//////////////////////////
// memory protection flags
//////////////////////////

/* `/include/uapi/asm-generic/mman-common.h` from kernel source tree. */

#define PROT_READ 0x1  /* page can be read */
#define PROT_WRITE 0x2 /* page can be written */
#define PROT_EXEC 0x4  /* page can be executed */
#define PROT_SEM 0x8   /* page may be used for atomic ops */
/*			0x10		   reserved for arch-specific use */
/*			0x20		   reserved for arch-specific use */
#define PROT_NONE 0x0		  /* page can not be accessed */
#define PROT_GROWSDOWN 0x01000000 /* mprotect flag: extend change to start of growsdown vma */
#define PROT_GROWSUP 0x02000000	  /* mprotect flag: extend change to end of growsup vma */

/* `/arch/powerpc/include/uapi/asm/mman.h` from kernel source tree. */

#define PROT_SAO 0x10 /* Strong Access Ordering */

//////////////////////////
// mmap flags
//////////////////////////

/* `/include/uapi/linux/mman.h` from kernel source tree. */

#define MAP_SHARED 0x01		 /* Share changes */
#define MAP_PRIVATE 0x02	 /* Changes are private */
#define MAP_SHARED_VALIDATE 0x03 /* share + validate extension flags */

/* `/include/uapi/asm-generic/mman-common.h` from kernel source tree. */

#define MAP_TYPE 0x0f	   /* Mask for type of mapping */
#define MAP_FIXED 0x10	   /* Interpret addr exactly */
#define MAP_ANONYMOUS 0x20 /* don't use a file */
#define MAP_FILE 0	   /* compatibility flags */

/* `/arch/x86/include/uapi/asm/mman.h` from kernel source tree. */

#define MAP_32BIT 0x40 /* only give out 32bit addresses */

/* `/arch/mips/include/uapi/asm/mman.h` from kernel source tree. */

#define MAP_RENAME 0x020 /* Assign page to file */

/* `/include/uapi/asm-generic/mman.h` from kernel source tree. */

#define MAP_GROWSDOWN 0x0100  /* stack-like segment */
#define MAP_DENYWRITE 0x0800  /* ETXTBSY */
#define MAP_EXECUTABLE 0x1000 /* mark it as an executable */
#define MAP_LOCKED 0x2000     /* pages are locked */
#define MAP_NORESERVE 0x4000  /* don't check for reservations */
#define MAP_POPULATE 0x8000   /* populate (prefault) pagetables */
#define MAP_NONBLOCK 0x10000  /* do not block on IO */
#define MAP_STACK 0x20000     /* give out an address that is best suited for process/thread stacks */
#define MAP_HUGETLB 0x40000   /* create a huge page mapping */
#define MAP_SYNC 0x80000      /* perform synchronous page faults for the mapping */

/* `/arch/sparc/include/uapi/asm/mman.h` from kernel source tree. */

#define MAP_INHERIT 0x80 /* SunOS doesn't do this, but... */

//////////////////////////
// fnctl flags
//////////////////////////

/* `/include/uapi/asm-generic/fnctl.h` from kernel source tree. */

#define F_DUPFD 0 /* dup */
#define F_GETFD 1 /* get close_on_exec */
#define F_SETFD 2 /* set/clear close_on_exec */
#define F_GETFL 3 /* get file->f_flags */
#define F_SETFL 4 /* set file->f_flags */
#define F_GETLK 5
#define F_SETLK 6
#define F_SETLKW 7
#define F_SETOWN 8   /* for sockets. */
#define F_GETOWN 9   /* for sockets. */
#define F_SETSIG 10  /* for sockets. */
#define F_GETSIG 11  /* for sockets. */
#define F_GETLK64 12 /*  using 'struct flock64' */
#define F_SETLK64 13
#define F_SETLKW64 14
#define F_SETOWN_EX 15
#define F_GETOWN_EX 16
#define F_GETOWNER_UIDS 17

#define F_OFD_GETLK 36
#define F_OFD_SETLK 37
#define F_OFD_SETLKW 38

/* `/include/uapi/linux/fnctl.h` from kernel source tree. */

#define F_LINUX_SPECIFIC_BASE 1024

#define F_SETLEASE (F_LINUX_SPECIFIC_BASE + 0)
#define F_GETLEASE (F_LINUX_SPECIFIC_BASE + 1)
#define F_NOTIFY (F_LINUX_SPECIFIC_BASE + 2)	    /* Request nofications on a directory. */
#define F_CANCELLK (F_LINUX_SPECIFIC_BASE + 5)	    /* Cancel a blocking posix lock. */
#define F_DUPFD_CLOEXEC (F_LINUX_SPECIFIC_BASE + 6) /* Create a file descriptor with FD_CLOEXEC set. */
/* Set and get of pipe page size array */
#define F_SETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 7)
#define F_GETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 8)

//////////////////////////
// setsockopt levels
//////////////////////////

/* `/include/uapi/asm-generic/socket.h` from kernel source tree. */

#define SOL_SOCKET 1

/* `/include/linux/socket.h` from kernel source tree. */

#define SOL_TCP 6

//////////////////////////
// setsockopt optname
//////////////////////////

/* `/include/uapi/asm-generic/socket.h` from kernel source tree. */

#define SO_DEBUG 1
#define SO_REUSEADDR 2
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_DONTROUTE 5
#define SO_BROADCAST 6
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_SNDBUFFORCE 32
#define SO_RCVBUFFORCE 33
#define SO_KEEPALIVE 9
#define SO_OOBINLINE 10
#define SO_NO_CHECK 11
#define SO_PRIORITY 12
#define SO_LINGER 13
#define SO_BSDCOMPAT 14
#define SO_REUSEPORT 15
#define SO_PASSCRED 16
#define SO_PEERCRED 17
#define SO_RCVLOWAT 18
#define SO_SNDLOWAT 19

/* Define all flavours just to be sure to catch at least one of them
 * https://github.com/torvalds/linux/commit/a9beb86ae6e55bd92f38453c8623de60b8e5a308
 */
#define SO_RCVTIMEO 20
#define SO_RCVTIMEO_OLD 20
#define SO_RCVTIMEO_NEW 66
#define SO_SNDTIMEO 21
#define SO_SNDTIMEO_OLD 21
#define SO_SNDTIMEO_NEW 67

/* Security levels - as per NRL IPv6 - don't actually do anything */
#define SO_SECURITY_AUTHENTICATION 22
#define SO_SECURITY_ENCRYPTION_TRANSPORT 23
#define SO_SECURITY_ENCRYPTION_NETWORK 24

#define SO_BINDTODEVICE 25

/* Socket filtering */
#define SO_ATTACH_FILTER 26
#define SO_DETACH_FILTER 27
#define SO_GET_FILTER SO_ATTACH_FILTER

#define SO_PEERNAME 28

#define SO_ACCEPTCONN 30

#define SO_PEERSEC 31
#define SO_PASSSEC 34

#define SO_MARK 36

#define SO_PROTOCOL 38
#define SO_DOMAIN 39

#define SO_RXQ_OVFL 40

#define SO_WIFI_STATUS 41
#define SCM_WIFI_STATUS SO_WIFI_STATUS
#define SO_PEEK_OFF 42

/* Instruct lower device to use last 4-bytes of skb data as FCS */
#define SO_NOFCS 43

#define SO_LOCK_FILTER 44

#define SO_SELECT_ERR_QUEUE 45

#define SO_BUSY_POLL 46

#define SO_MAX_PACING_RATE 47

#define SO_BPF_EXTENSIONS 48

#define SO_INCOMING_CPU 49

#define SO_ATTACH_BPF 50
#define SO_DETACH_BPF SO_DETACH_FILTER

#define SO_ATTACH_REUSEPORT_CBPF 51
#define SO_ATTACH_REUSEPORT_EBPF 52

#define SO_CNX_ADVICE 53

#define SCM_TIMESTAMPING_OPT_STATS 54

#define SO_MEMINFO 55

#define SO_INCOMING_NAPI_ID 56

#define SO_COOKIE 57

#define SCM_TIMESTAMPING_PKTINFO 58

#define SO_PEERGROUPS 59

#define SO_ZEROCOPY 60

#define SO_TXTIME 61
#define SCM_TXTIME SO_TXTIME

#define SO_BINDTOIFINDEX 62

/* We keep names without `OLD` for compatibility with our `sockopt_optname_to_scap()`
 */
#define SO_TIMESTAMP 29	   /* SO_TIMESTAMP_OLD */
#define SO_TIMESTAMPNS 35  /* SO_TIMESTAMPNS_OLD */
#define SO_TIMESTAMPING 37 /* SO_TIMESTAMPING_OLD */

#define SO_TIMESTAMP_NEW 63
#define SO_TIMESTAMPNS_NEW 64
#define SO_TIMESTAMPING_NEW 65

#define SO_RCVTIMEO_NEW 66
#define SO_SNDTIMEO_NEW 67

#define SO_DETACH_REUSEPORT_BPF 68

#define SO_PREFER_BUSY_POLL 69
#define SO_BUSY_POLL_BUDGET 70

#define SO_NETNS_COOKIE 71

#define SO_BUF_LOCK 72

#define SO_RESERVE_MEM 73

//////////////////////////
// poll events
//////////////////////////

/* `/include/uapi/asm-generic/poll.h` from kernel source tree. */

/* These are specified by iBCS2 */
#define POLLIN 0x0001
#define POLLPRI 0x0002
#define POLLOUT 0x0004
#define POLLERR 0x0008
#define POLLHUP 0x0010
#define POLLNVAL 0x0020

/* The rest seem to be more-or-less nonstandard. */
#define POLLRDNORM 0x0040
#define POLLRDBAND 0x0080
#define POLLWRNORM 0x0100
#define POLLWRBAND 0x0200
#define POLLMSG 0x0400
#define POLLREMOVE 0x1000
#define POLLRDHUP 0x2000

//////////////////////////
// futex_op
//////////////////////////

/* `/include/uapi/linux/futex.h` from kernel source tree. */

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_FD 2
#define FUTEX_REQUEUE 3
#define FUTEX_CMP_REQUEUE 4
#define FUTEX_WAKE_OP 5
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define FUTEX_LOCK_PI2 13

#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_CLOCK_REALTIME 256

//////////////////////////
// access flags
//////////////////////////

/* `/include/linux/fs.h` from kernel source tree. */

#define MAY_EXEC 0x00000001
#define MAY_WRITE 0x00000002
#define MAY_READ 0x00000004

//////////////////////////
// lseek whence
//////////////////////////

/* `/include/uapi/linux/fs.h` from kernel source tree. */

#define SEEK_SET 0  /* seek relative to beginning of file */
#define SEEK_CUR 1  /* seek relative to current file position */
#define SEEK_END 2  /* seek relative to end of file */
#define SEEK_DATA 3 /* seek to the next data */
#define SEEK_HOLE 4 /* seek to the next hole */
#define SEEK_MAX SEEK_HOLE

//////////////////////////
// flock flags
//////////////////////////

/* `/include/uapi/asm-generic/fcntl.h` from kernel source tree. */

/* operations for bsd flock(), also used by the kernel implementation */
#define LOCK_SH 1 /* shared lock */
#define LOCK_EX 2 /* exclusive lock */
#define LOCK_NB 4 /* or'd with one of the above to prevent blocking */
#define LOCK_UN 8 /* remove lock */

//////////////////////////
// quotactl types/cmd/fmt
//////////////////////////

/* `/include/uapi/linux/quota.h` from kernel source tree. */

/* types */
#define MAXQUOTAS 3
#define USRQUOTA 0 /* element used for user quotas */
#define GRPQUOTA 1 /* element used for group quotas */
#define PRJQUOTA 2 /* element used for project quotas */

/* Command definitions for the 'quotactl' system call. */
#define SUBCMDMASK 0x00ff
#define SUBCMDSHIFT 8

#define Q_SYNC 0x800001		/* sync disk copy of a filesystems quotas */
#define Q_QUOTAON 0x800002	/* turn quotas on */
#define Q_QUOTAOFF 0x800003	/* turn quotas off */
#define Q_GETFMT 0x800004	/* get quota format used on given filesystem */
#define Q_GETINFO 0x800005	/* get information about quota files */
#define Q_SETINFO 0x800006	/* set information about quota files */
#define Q_GETQUOTA 0x800007	/* get user quota structure */
#define Q_SETQUOTA 0x800008	/* set user quota structure */
#define Q_GETNEXTQUOTA 0x800009 /* get disk limits and usage >= ID */

/* Quota format type IDs */
#define QFMT_VFS_OLD 1
#define QFMT_VFS_V0 2
#define QFMT_OCFS2 3
#define QFMT_VFS_V1 4

/*
 * Disk quota - quotactl(2) commands for the XFS Quota Manager (XQM).
 */

/* `/include/uapi/linux/dqblk_xfs.h` from kernel source tree. */

#define XQM_CMD(x) (('X' << 8) + (x))			   /* note: forms first QCMD argument */
#define XQM_COMMAND(x) (((x) & (0xff << 8)) == ('X' << 8)) /* test if for XFS */

#define XQM_USRQUOTA 0 /* system call user quota type */
#define XQM_GRPQUOTA 1 /* system call group quota type */
#define XQM_PRJQUOTA 2 /* system call project quota type */
#define XQM_MAXQUOTAS 3

#define Q_XQUOTAON XQM_CMD(1)	   /* enable accounting/enforcement */
#define Q_XQUOTAOFF XQM_CMD(2)	   /* disable accounting/enforcement */
#define Q_XGETQUOTA XQM_CMD(3)	   /* get disk limits and usage */
#define Q_XSETQLIM XQM_CMD(4)	   /* set disk limits */
#define Q_XGETQSTAT XQM_CMD(5)	   /* get quota subsystem status */
#define Q_XQUOTARM XQM_CMD(6)	   /* free disk space used by dquots */
#define Q_XQUOTASYNC XQM_CMD(7)	   /* delalloc flush, updates dquots */
#define Q_XGETQSTATV XQM_CMD(8)	   /* newer version of get quota */
#define Q_XGETNEXTQUOTA XQM_CMD(9) /* get disk limits and usage >= ID */

//////////////////////////
// semctl/semget/semop flags
//////////////////////////

/* `/include/uapi/linux/ipc.h` from kernel source tree. */

/* resource get request flags */
#define IPC_CREAT 00001000  /* create if key is nonexistent */
#define IPC_EXCL 00002000   /* fail if key exists */
#define IPC_NOWAIT 00004000 /* return error on wait */

/*
 * Control commands used with semctl, msgctl and shmctl
 * see also specific commands in sem.h, msg.h and shm.h
 */
#define IPC_RMID 0 /* remove resource */
#define IPC_SET 1  /* set ipc_perm options */
#define IPC_STAT 2 /* get ipc_perm options */
#define IPC_INFO 3 /* see ipcs */

/* `/include/uapi/linux/sem.h` from kernel source tree. */

/* semctl Command Definitions. */
#define GETPID 11  /* get sempid */
#define GETVAL 12  /* get semval */
#define GETALL 13  /* get all semval's */
#define GETNCNT 14 /* get semncnt */
#define GETZCNT 15 /* get semzcnt */
#define SETVAL 16  /* set semval */
#define SETALL 17  /* set all semval's */

/* ipcs ctl cmds */
#define SEM_STAT 18
#define SEM_INFO 19
#define SEM_STAT_ANY 20

/* semop flags */
#define SEM_UNDO 0x1000 /* undo the operation on exit. */

//////////////////////////
// mlockall flags
//////////////////////////

/* `/include/uapi/asm-generic/mman.h` from kernel source tree. */

#define MCL_CURRENT 1 /* lock all current mappings */
#define MCL_FUTURE 2  /* lock all future mappings */
#define MCL_ONFAULT 4 /* lock all pages that are faulted in */

//////////////////////////
// chmod modes
//////////////////////////

/* `/include/uapi/linux/stat.h` from kernel source tree. */

#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000

#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

//////////////////////////
// epoll_create1 flags
//////////////////////////

#define EPOLL_CLOEXEC 02000000

//////////////////////////
// mlock2 flags
//////////////////////////

/* `/include/uapi/asm-generic/mman-common.h` from kernel source tree. */

#define MLOCK_ONFAULT 0x01 /* Lock pages in range after they are faulted in, do not prefault */

//////////////////////////
// mlockall flags
//////////////////////////

/* `/include/uapi/asm-generic/mman.h` from kernel source tree. */

#define MCL_CURRENT 1 /* lock all current mappings */
#define MCL_FUTURE 2  /* lock all future mappings */
#define MCL_ONFAULT 4 /* lock all pages that are faulted in */

/*=============================== FLAGS ===========================*/

/*=============================== PROTOCOL/ADDRESS FAMILIES ===========================*/

//////////////////////////
// Address families
//////////////////////////

/* `/include/linux/socket.h` from kernel source tree. */

#define AF_UNSPEC 0
#define AF_UNIX 1      /* Unix domain sockets 		*/
#define AF_LOCAL 1     /* POSIX name for AF_UNIX	*/
#define AF_INET 2      /* Internet IP Protocol 	*/
#define AF_AX25 3      /* Amateur Radio AX.25 		*/
#define AF_IPX 4       /* Novell IPX 			*/
#define AF_APPLETALK 5 /* AppleTalk DDP 		*/
#define AF_NETROM 6    /* Amateur Radio NET/ROM 	*/
#define AF_BRIDGE 7    /* Multiprotocol bridge 	*/
#define AF_ATMPVC 8    /* ATM PVCs			*/
#define AF_X25 9       /* Reserved for X.25 project 	*/
#define AF_INET6 10    /* IP version 6			*/
#define AF_ROSE 11     /* Amateur Radio X.25 PLP	*/
#define AF_DECnet 12   /* Reserved for DECnet project	*/
#define AF_NETBEUI 13  /* Reserved for 802.2LLC project*/
#define AF_SECURITY 14 /* Security callback pseudo AF */
#define AF_KEY 15      /* PF_KEY key management API */
#define AF_NETLINK 16
#define AF_ROUTE AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET 17	    /* Packet family		*/
#define AF_ASH 18	    /* Ash				*/
#define AF_ECONET 19	    /* Acorn Econet			*/
#define AF_ATMSVC 20	    /* ATM SVCs			*/
#define AF_RDS 21	    /* RDS sockets 			*/
#define AF_SNA 22	    /* Linux SNA Project (nutters!) */
#define AF_IRDA 23	    /* IRDA sockets			*/
#define AF_PPPOX 24	    /* PPPoX sockets		*/
#define AF_WANPIPE 25	    /* Wanpipe API Sockets */
#define AF_LLC 26	    /* Linux LLC			*/
#define AF_IB 27	    /* Native InfiniBand address	*/
#define AF_MPLS 28	    /* MPLS */
#define AF_CAN 29	    /* Controller Area Network      */
#define AF_TIPC 30	    /* TIPC sockets			*/
#define AF_BLUETOOTH 31	    /* Bluetooth sockets 		*/
#define AF_IUCV 32	    /* IUCV sockets			*/
#define AF_RXRPC 33	    /* RxRPC sockets 		*/
#define AF_ISDN 34	    /* mISDN sockets 		*/
#define AF_PHONET 35	    /* Phonet sockets		*/
#define AF_IEEE802154 36    /* IEEE802154 sockets		*/
#define AF_CAIF 37	    /* CAIF sockets			*/
#define AF_ALG 38	    /* Algorithm sockets		*/
#define AF_NFC 39	    /* NFC sockets			*/
#define AF_VSOCK 40	    /* vSockets			*/
#define AF_KCM 41	    /* Kernel Connection Multiplexor*/
#define AF_QIPCRTR 42	    /* Qualcomm IPC Router          */
#define AF_SMC 43	    /* smc sockets: reserve number for PF_SMC protocol family that reuses AF_INET address family */
#define AF_XDP 44	    /* XDP sockets */
#define AF_MCTP 45	    /* Management component transport protocol */
#define AF_MAX 46	    /* For now.. */

//////////////////////////
// Protocol families
//////////////////////////

/* `/include/linux/socket.h` from kernel source tree. */

#define PF_UNSPEC AF_UNSPEC
#define PF_UNIX AF_UNIX
#define PF_LOCAL AF_LOCAL
#define PF_INET AF_INET
#define PF_AX25 AF_AX25
#define PF_IPX AF_IPX
#define PF_APPLETALK AF_APPLETALK
#define PF_NETROM AF_NETROM
#define PF_BRIDGE AF_BRIDGE
#define PF_ATMPVC AF_ATMPVC
#define PF_X25 AF_X25
#define PF_INET6 AF_INET6
#define PF_ROSE AF_ROSE
#define PF_DECnet AF_DECnet
#define PF_NETBEUI AF_NETBEUI
#define PF_SECURITY AF_SECURITY
#define PF_KEY AF_KEY
#define PF_NETLINK AF_NETLINK
#define PF_ROUTE AF_ROUTE
#define PF_PACKET AF_PACKET
#define PF_ASH AF_ASH
#define PF_ECONET AF_ECONET
#define PF_ATMSVC AF_ATMSVC
#define PF_RDS AF_RDS
#define PF_SNA AF_SNA
#define PF_IRDA AF_IRDA
#define PF_PPPOX AF_PPPOX
#define PF_WANPIPE AF_WANPIPE
#define PF_LLC AF_LLC
#define PF_IB AF_IB
#define PF_MPLS AF_MPLS
#define PF_CAN AF_CAN
#define PF_TIPC AF_TIPC
#define PF_BLUETOOTH AF_BLUETOOTH
#define PF_IUCV AF_IUCV
#define PF_RXRPC AF_RXRPC
#define PF_ISDN AF_ISDN
#define PF_PHONET AF_PHONET
#define PF_IEEE802154 AF_IEEE802154
#define PF_CAIF AF_CAIF
#define PF_ALG AF_ALG
#define PF_NFC AF_NFC
#define PF_VSOCK AF_VSOCK
#define PF_KCM AF_KCM
#define PF_QIPCRTR AF_QIPCRTR
#define PF_SMC AF_SMC
#define PF_XDP AF_XDP
#define PF_MCTP AF_MCTP
#define PF_MAX AF_MAX

/*=============================== PROTOCOL/ADDRESS FAMILIES ===========================*/

/*=============================== PTRACE REQUESTS ===========================*/

/* `/include/uapi/linux/ptrace.h` from kernel source tree.  */

#define PTRACE_TRACEME 0
#define PTRACE_PEEKTEXT 1
#define PTRACE_PEEKDATA 2
#define PTRACE_PEEKUSR 3
#define PTRACE_POKETEXT 4
#define PTRACE_POKEDATA 5
#define PTRACE_POKEUSR 6
#define PTRACE_CONT 7
#define PTRACE_KILL 8
#define PTRACE_SINGLESTEP 9

#define PTRACE_ATTACH 16
#define PTRACE_DETACH 17

#define PTRACE_SYSCALL 24

/* 0x4200-0x4300 are reserved for architecture-independent additions.  */
#define PTRACE_SETOPTIONS 0x4200
#define PTRACE_GETEVENTMSG 0x4201
#define PTRACE_GETSIGINFO 0x4202
#define PTRACE_SETSIGINFO 0x4203
#define PTRACE_GETREGSET 0x4204
#define PTRACE_SETREGSET 0x4205
#define PTRACE_SEIZE 0x4206
#define PTRACE_INTERRUPT 0x4207
#define PTRACE_LISTEN 0x4208
#define PTRACE_PEEKSIGINFO 0x4209
#define PTRACE_GETSIGMASK 0x420a
#define PTRACE_SETSIGMASK 0x420b
#define PTRACE_SECCOMP_GET_FILTER 0x420c

/* `/arch/x86/include/uapi/asm/ptrace-abi.h` from kernel source tree.  */

#if defined(__TARGET_ARCH_x86)
#define PTRACE_GETREGS 12
#define PTRACE_SETREGS 13
#define PTRACE_GETFPREGS 14
#define PTRACE_SETFPREGS 15

#define PTRACE_GETFPXREGS 18
#define PTRACE_SETFPXREGS 19

#define PTRACE_OLDSETOPTIONS 21

/* only useful for access 32bit programs / kernels */
#define PTRACE_GET_THREAD_AREA 25
#define PTRACE_SET_THREAD_AREA 26

#define PTRACE_ARCH_PRCTL 30
#define PTRACE_SYSEMU 31
#define PTRACE_SYSEMU_SINGLESTEP 32
#define PTRACE_SINGLEBLOCK 33 /* resume execution until next branch */
#endif

/*=============================== PTRACE REQUESTS ===========================*/

/*=============================== CAPABILITIES ===========================*/

/* `/include/uapi/linux/capability.h` from kernel source tree. */

/* In a system with the [_POSIX_CHOWN_RESTRICTED] option defined, this
   overrides the restriction of changing file ownership and group
   ownership. */

#define CAP_CHOWN 0

/* Override all DAC access, including ACL execute access if
   [_POSIX_ACL] is defined. Excluding DAC access covered by
   CAP_LINUX_IMMUTABLE. */

#define CAP_DAC_OVERRIDE 1

/* Overrides all DAC restrictions regarding read and search on files
   and directories, including ACL restrictions if [_POSIX_ACL] is
   defined. Excluding DAC access covered by CAP_LINUX_IMMUTABLE. */

#define CAP_DAC_READ_SEARCH 2

/* Overrides all restrictions about allowed operations on files, where
   file owner ID must be equal to the user ID, except where CAP_FSETID
   is applicable. It doesn't override MAC and DAC restrictions. */

#define CAP_FOWNER 3

/* Overrides the following restrictions that the effective user ID
   shall match the file owner ID when setting the S_ISUID and S_ISGID
   bits on that file; that the effective group ID (or one of the
   supplementary group IDs) shall match the file owner ID when setting
   the S_ISGID bit on that file; that the S_ISUID and S_ISGID bits are
   cleared on successful return from chown(2) (not implemented). */

#define CAP_FSETID 4

/* Overrides the restriction that the real or effective user ID of a
   process sending a signal must match the real or effective user ID
   of the process receiving the signal. */

#define CAP_KILL 5

/* Allows setgid(2) manipulation */
/* Allows setgroups(2) */
/* Allows forged gids on socket credentials passing. */

#define CAP_SETGID 6

/* Allows set*uid(2) manipulation (including fsuid). */
/* Allows forged pids on socket credentials passing. */

#define CAP_SETUID 7

/**
 ** Linux-specific capabilities
 **/

/* Without VFS support for capabilities:
 *   Transfer any capability in your permitted set to any pid,
 *   remove any capability in your permitted set from any pid
 * With VFS support for capabilities (neither of above, but)
 *   Add any capability from current's capability bounding set
 *       to the current process' inheritable set
 *   Allow taking bits out of capability bounding set
 *   Allow modification of the securebits for a process
 */

#define CAP_SETPCAP 8

/* Allow modification of S_IMMUTABLE and S_APPEND file attributes */

#define CAP_LINUX_IMMUTABLE 9

/* Allows binding to TCP/UDP sockets below 1024 */
/* Allows binding to ATM VCIs below 32 */

#define CAP_NET_BIND_SERVICE 10

/* Allow broadcasting, listen to multicast */

#define CAP_NET_BROADCAST 11

/* Allow interface configuration */
/* Allow administration of IP firewall, masquerading and accounting */
/* Allow setting debug option on sockets */
/* Allow modification of routing tables */
/* Allow setting arbitrary process / process group ownership on
   sockets */
/* Allow binding to any address for transparent proxying (also via NET_RAW) */
/* Allow setting TOS (type of service) */
/* Allow setting promiscuous mode */
/* Allow clearing driver statistics */
/* Allow multicasting */
/* Allow read/write of device-specific registers */
/* Allow activation of ATM control sockets */

#define CAP_NET_ADMIN 12

/* Allow use of RAW sockets */
/* Allow use of PACKET sockets */
/* Allow binding to any address for transparent proxying (also via NET_ADMIN) */

#define CAP_NET_RAW 13

/* Allow locking of shared memory segments */
/* Allow mlock and mlockall (which doesn't really have anything to do
   with IPC) */

#define CAP_IPC_LOCK 14

/* Override IPC ownership checks */

#define CAP_IPC_OWNER 15

/* Insert and remove kernel modules - modify kernel without limit */
#define CAP_SYS_MODULE 16

/* Allow ioperm/iopl access */
/* Allow sending USB messages to any device via /dev/bus/usb */

#define CAP_SYS_RAWIO 17

/* Allow use of chroot() */

#define CAP_SYS_CHROOT 18

/* Allow ptrace() of any process */

#define CAP_SYS_PTRACE 19

/* Allow configuration of process accounting */

#define CAP_SYS_PACCT 20

/* Allow configuration of the secure attention key */
/* Allow administration of the random device */
/* Allow examination and configuration of disk quotas */
/* Allow setting the domainname */
/* Allow setting the hostname */
/* Allow mount() and umount(), setting up new smb connection */
/* Allow some autofs root ioctls */
/* Allow nfsservctl */
/* Allow VM86_REQUEST_IRQ */
/* Allow to read/write pci config on alpha */
/* Allow irix_prctl on mips (setstacksize) */
/* Allow flushing all cache on m68k (sys_cacheflush) */
/* Allow removing semaphores */
/* Used instead of CAP_CHOWN to "chown" IPC message queues, semaphores
   and shared memory */
/* Allow locking/unlocking of shared memory segment */
/* Allow turning swap on/off */
/* Allow forged pids on socket credentials passing */
/* Allow setting readahead and flushing buffers on block devices */
/* Allow setting geometry in floppy driver */
/* Allow turning DMA on/off in xd driver */
/* Allow administration of md devices (mostly the above, but some
   extra ioctls) */
/* Allow tuning the ide driver */
/* Allow access to the nvram device */
/* Allow administration of apm_bios, serial and bttv (TV) device */
/* Allow manufacturer commands in isdn CAPI support driver */
/* Allow reading non-standardized portions of pci configuration space */
/* Allow DDI debug ioctl on sbpcd driver */
/* Allow setting up serial ports */
/* Allow sending raw qic-117 commands */
/* Allow enabling/disabling tagged queuing on SCSI controllers and sending
   arbitrary SCSI commands */
/* Allow setting encryption key on loopback filesystem */
/* Allow setting zone reclaim policy */
/* Allow everything under CAP_BPF and CAP_PERFMON for backward compatibility */

#define CAP_SYS_ADMIN 21

/* Allow use of reboot() */

#define CAP_SYS_BOOT 22

/* Allow raising priority and setting priority on other (different
   UID) processes */
/* Allow use of FIFO and round-robin (realtime) scheduling on own
   processes and setting the scheduling algorithm used by another
   process. */
/* Allow setting cpu affinity on other processes */
/* Allow setting realtime ioprio class */
/* Allow setting ioprio class on other processes */

#define CAP_SYS_NICE 23

/* Override resource limits. Set resource limits. */
/* Override quota limits. */
/* Override reserved space on ext2 filesystem */
/* Modify data journaling mode on ext3 filesystem (uses journaling
   resources) */
/* NOTE: ext2 honors fsuid when checking for resource overrides, so
   you can override using fsuid too */
/* Override size restrictions on IPC message queues */
/* Allow more than 64hz interrupts from the real-time clock */
/* Override max number of consoles on console allocation */
/* Override max number of keymaps */
/* Control memory reclaim behavior */

#define CAP_SYS_RESOURCE 24

/* Allow manipulation of system clock */
/* Allow irix_stime on mips */
/* Allow setting the real-time clock */

#define CAP_SYS_TIME 25

/* Allow configuration of tty devices */
/* Allow vhangup() of tty */

#define CAP_SYS_TTY_CONFIG 26

/* Allow the privileged aspects of mknod() */

#define CAP_MKNOD 27

/* Allow taking of leases on files */

#define CAP_LEASE 28

/* Allow writing the audit log via unicast netlink socket */

#define CAP_AUDIT_WRITE 29

/* Allow configuration of audit via unicast netlink socket */

#define CAP_AUDIT_CONTROL 30

/* Set or remove capabilities on files.
   Map uid=0 into a child user namespace. */

#define CAP_SETFCAP 31

/* Override MAC access.
   The base kernel enforces no MAC policy.
   An LSM may enforce a MAC policy, and if it does and it chooses
   to implement capability based overrides of that policy, this is
   the capability it should use to do so. */

#define CAP_MAC_OVERRIDE 32

/* Allow MAC configuration or state changes.
   The base kernel requires no MAC configuration.
   An LSM may enforce a MAC policy, and if it does and it chooses
   to implement capability based checks on modifications to that
   policy or the data required to maintain it, this is the
   capability it should use to do so. */

#define CAP_MAC_ADMIN 33

/* Allow configuring the kernel's syslog (printk behaviour) */

#define CAP_SYSLOG 34

/* Allow triggering something that will wake the system */

#define CAP_WAKE_ALARM 35

/* Allow preventing system suspends */

#define CAP_BLOCK_SUSPEND 36

/* Allow reading the audit log via multicast netlink socket */

#define CAP_AUDIT_READ 37

/*
 * Allow system performance and observability privileged operations
 * using perf_events, i915_perf and other kernel subsystems
 */

#define CAP_PERFMON 38

/*
 * CAP_BPF allows the following BPF operations:
 * - Creating all types of BPF maps
 * - Advanced verifier features
 *   - Indirect variable access
 *   - Bounded loops
 *   - BPF to BPF function calls
 *   - Scalar precision tracking
 *   - Larger complexity limits
 *   - Dead code elimination
 *   - And potentially other features
 * - Loading BPF Type Format (BTF) data
 * - Retrieve xlated and JITed code of BPF programs
 * - Use bpf_spin_lock() helper
 *
 * CAP_PERFMON relaxes the verifier checks further:
 * - BPF progs can use of pointer-to-integer conversions
 * - speculation attack hardening measures are bypassed
 * - bpf_probe_read to read arbitrary kernel memory is allowed
 * - bpf_trace_printk to print kernel memory is allowed
 *
 * CAP_SYS_ADMIN is required to use bpf_probe_write_user.
 *
 * CAP_SYS_ADMIN is required to iterate system wide loaded
 * programs, maps, links, BTFs and convert their IDs to file descriptors.
 *
 * CAP_PERFMON and CAP_BPF are required to load tracing programs.
 * CAP_NET_ADMIN and CAP_BPF are required to load networking programs.
 */
#define CAP_BPF 39

/* Allow checkpoint/restore related operations */
/* Allow PID selection during clone3() */
/* Allow writing to ns_last_pid */

#define CAP_CHECKPOINT_RESTORE 40

#define CAP_LAST_CAP CAP_CHECKPOINT_RESTORE

/*=============================== CAPABILITIES ===========================*/

/*=============================== DIRECTORY_NOTIFICATIONS ===========================*/

/*
 * Types of directory notifications that may be requested.
 */
#define DN_ACCESS 0x00000001	/* File accessed */
#define DN_MODIFY 0x00000002	/* File modified */
#define DN_CREATE 0x00000004	/* File created */
#define DN_DELETE 0x00000008	/* File removed */
#define DN_RENAME 0x00000010	/* File renamed */
#define DN_ATTRIB 0x00000020	/* File changed attibutes */
#define DN_MULTISHOT 0x80000000 /* Don't remove notifier */

#define AT_FDCWD -100		  /* Special value used to indicate \
				     openat should use the current  \
				     working directory. */
#define AT_SYMLINK_NOFOLLOW 0x100 /* Do not follow symbolic links.  */
#define AT_REMOVEDIR 0x200	  /* Remove directory instead of \
				     unlinking file.  */
#define AT_SYMLINK_FOLLOW 0x400	  /* Follow symbolic links.  */
#define AT_NO_AUTOMOUNT 0x800	  /* Suppress terminal automount traversal */
#define AT_EMPTY_PATH 0x1000	  /* Allow empty relative pathname */

#define AT_STATX_SYNC_TYPE 0x6000    /* Type of synchronisation required from statx() */
#define AT_STATX_SYNC_AS_STAT 0x0000 /* - Do whatever stat() does */
#define AT_STATX_FORCE_SYNC 0x2000   /* - Force the attributes to be sync'd with the server */
#define AT_STATX_DONT_SYNC 0x4000    /* - Don't sync attributes with the server */

/*=============================== DIRECTORY_NOTIFICATIONS ===========================*/

/*=============================== DEVICE_VERSIONS ===========================*/

/* `/include/linux/kdev_t.h` from kernel source tree. */

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MAJOR(dev) ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev) ((unsigned int)((dev)&MINORMASK))
#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

/*=============================== DEVICE_VERSIONS ===========================*/

/*=============================== RLIMIT_ID ===========================*/

/* `/include/uapi/asm-generic/resource.h` from kernel source tree. */

#define RLIMIT_CPU 0	     /* CPU time in sec */
#define RLIMIT_FSIZE 1	     /* Maximum filesize */
#define RLIMIT_DATA 2	     /* max data size */
#define RLIMIT_STACK 3	     /* max stack size */
#define RLIMIT_CORE 4	     /* max core file size */
#define RLIMIT_RSS 5	     /* max resident set size */
#define RLIMIT_NPROC 6	     /* max number of processes */
#define RLIMIT_NOFILE 7	     /* max number of open files */
#define RLIMIT_MEMLOCK 8     /* max locked-in-memory address space */
#define RLIMIT_AS 9	     /* address space limit */
#define RLIMIT_LOCKS 10	     /* maximum file locks held */
#define RLIMIT_SIGPENDING 11 /* max number of pending signals */
#define RLIMIT_MSGQUEUE 12   /* maximum bytes in POSIX mqueues */
#define RLIMIT_NICE 13	     /* max nice prio allowed to raise to 0-39 for nice level 19 .. -20 */
#define RLIMIT_RTPRIO 14     /* maximum realtime priority */
#define RLIMIT_RTTIME 15     /* timeout for RT tasks in us */
#define RLIM_NLIMITS 16

/*=============================== RLIMIT_ID ===========================*/

/*=============================== HOST_TO_NETWORK_BYTE_ORDER ===========================*/

/* Swap bytes in 16 bit value.  */
#define __bswap_constant_16(x) \
	((unsigned short int)((((x) >> 8) & 0xff) | (((x)&0xff) << 8)))

/* Swap bytes in 32 bit value.  */
#define __bswap_constant_32(x)                                \
	((((x)&0xff000000) >> 24) | (((x)&0x00ff0000) >> 8) | \
	 (((x)&0x0000ff00) << 8) | (((x)&0x000000ff) << 24))

#define identity(x) x

/* The host byte order is the same as network byte order,
   so these functions are all just identity.  */
#ifdef __LITTLE_ENDIAN__
#define ntohl(x) __bswap_constant_32(x)
#define ntohs(x) __bswap_constant_16(x)
#define htonl(x) __bswap_constant_32(x)
#define htons(x) __bswap_constant_16(x)
#else
#define ntohl(x) identity(x)
#define ntohs(x) identity(x)
#define htonl(x) identity(x)
#define htons(x) identity(x)
#endif

/*=============================== HOST_TO_NETWORK_BYTE_ORDER ===========================*/

/*=============================== UNIX SOCKET PATH ===========================*/

/* `/include/uapi/linux/un.h` from kernel source tree. */

#define UNIX_PATH_MAX 108

/*=============================== UNIX SOCKET PATH ===========================*/

/*=============================== QUOTACTL SYSCALL ===========================*/

/* `/include/linux/quota.h` from kernel source tree. */

/* QIF_BLIMITS_B are defined in the vmlinux.h */

#define QIF_BLIMITS (1 << QIF_BLIMITS_B)
#define QIF_SPACE (1 << QIF_SPACE_B)
#define QIF_ILIMITS (1 << QIF_ILIMITS_B)
#define QIF_INODES (1 << QIF_INODES_B)
#define QIF_BTIME (1 << QIF_BTIME_B)
#define QIF_ITIME (1 << QIF_ITIME_B)
#define QIF_LIMITS (QIF_BLIMITS | QIF_ILIMITS)
#define QIF_USAGE (QIF_SPACE | QIF_INODES)
#define QIF_TIMES (QIF_BTIME | QIF_ITIME)
#define QIF_ALL (QIF_LIMITS | QIF_USAGE | QIF_TIMES)

/*
 * Structure used for setting quota information about file via quotactl
 * Following flags are used to specify which fields are valid
 */
#define IIF_BGRACE 1
#define IIF_IGRACE 2
#define IIF_FLAGS 4
#define IIF_ALL (IIF_BGRACE | IIF_IGRACE | IIF_FLAGS)

/*=============================== QUOTACTL SYSCALL ===========================*/

/*=============================== SPLICE SYSCALL =============================*/

#define SPLICE_F_MOVE	   (0x01)	
#define SPLICE_F_NONBLOCK  (0x02) 
#define SPLICE_F_MORE	   (0x04)	
#define SPLICE_F_GIFT	   (0x08)	

#define SPLICE_F_ALL (SPLICE_F_MOVE|SPLICE_F_NONBLOCK|SPLICE_F_MORE|SPLICE_F_GIFT)

/*=============================== SPLICE SYSCALL =============================*/

/*=============================== SOCKETCALL CODES ===========================*/

#define SYS_SOCKET 1	  /* sys_socket(2)		*/
#define SYS_BIND 2	  /* sys_bind(2)			*/
#define SYS_CONNECT 3	  /* sys_connect(2)		*/
#define SYS_LISTEN 4	  /* sys_listen(2)		*/
#define SYS_ACCEPT 5	  /* sys_accept(2)		*/
#define SYS_GETSOCKNAME 6 /* sys_getsockname(2)		*/
#define SYS_GETPEERNAME 7 /* sys_getpeername(2)		*/
#define SYS_SOCKETPAIR 8  /* sys_socketpair(2)		*/
#define SYS_SEND 9	  /* sys_send(2)			*/
#define SYS_RECV 10	  /* sys_recv(2)			*/
#define SYS_SENDTO 11	  /* sys_sendto(2)		*/
#define SYS_RECVFROM 12	  /* sys_recvfrom(2)		*/
#define SYS_SHUTDOWN 13	  /* sys_shutdown(2)		*/
#define SYS_SETSOCKOPT 14 /* sys_setsockopt(2)		*/
#define SYS_GETSOCKOPT 15 /* sys_getsockopt(2)		*/
#define SYS_SENDMSG 16	  /* sys_sendmsg(2)		*/
#define SYS_RECVMSG 17	  /* sys_recvmsg(2)		*/
#define SYS_ACCEPT4 18	  /* sys_accept4(2)		*/
#define SYS_RECVMMSG 19	  /* sys_recvmmsg(2)		*/
#define SYS_SENDMMSG 20	  /* sys_sendmmsg(2)		*/

/*=============================== SOCKETCALL CODES ===========================*/

#endif /* __MISSING_DEFINITIONS_H__ */
