/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef EVENTS_PUBLIC_H_
#define EVENTS_PUBLIC_H_

#if defined(__sun)
#include <sys/ioccom.h>
#endif

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include "../userspace/common/sysdig_types.h"
#endif

/*
 * Macros for packing in different build environments
 */
#if !defined(CYGWING_AGENT) && (defined(_WIN64) || defined(WIN64) || defined(_WIN32) || defined(WIN32))
#define _packed __pragma(pack(push, 1)); __pragma(pack(pop))
#else
#define _packed __attribute__((packed))
#endif

/*
 * Limits
 */
#define PPM_MAX_EVENT_PARAMS (1 << 5)	/* Max number of parameters an event can have */
#define PPM_MAX_PATH_SIZE 256	/* Max size that an event parameter can have in the circular buffer, in bytes */
#define PPM_MAX_NAME_LEN 32

/*
 * Socket families
 */
#define PPM_AF_UNSPEC       0
#define PPM_AF_UNIX         1       /* Unix domain sockets          */
#define PPM_AF_LOCAL        1       /* POSIX name for PPM_AF_UNIX   */
#define PPM_AF_INET         2       /* Internet IP Protocol         */
#define PPM_AF_AX25         3       /* Amateur Radio AX.25          */
#define PPM_AF_IPX          4       /* Novell IPX                   */
#define PPM_AF_APPLETALK    5       /* AppleTalk DDP                */
#define PPM_AF_NETROM       6       /* Amateur Radio NET/ROM        */
#define PPM_AF_BRIDGE       7       /* Multiprotocol bridge         */
#define PPM_AF_ATMPVC       8       /* ATM PVCs                     */
#define PPM_AF_X25          9       /* Reserved for X.25 project    */
#define PPM_AF_INET6        10      /* IP version 6                 */
#define PPM_AF_ROSE         11      /* Amateur Radio X.25 PLP       */
#define PPM_AF_DECnet       12      /* Reserved for DECnet project  */
#define PPM_AF_NETBEUI      13      /* Reserved for 802.2LLC project*/
#define PPM_AF_SECURITY     14      /* Security callback pseudo AF */
#define PPM_AF_KEY          15      /* PF_KEY key management API */
#define PPM_AF_NETLINK      16
#define PPM_AF_ROUTE        PPM_AF_NETLINK /* Alias to emulate 4.4BSD */
#define PPM_AF_PACKET       17      /* Packet family                */
#define PPM_AF_ASH          18      /* Ash                          */
#define PPM_AF_ECONET       19      /* Acorn Econet                 */
#define PPM_AF_ATMSVC       20      /* ATM SVCs                     */
#define PPM_AF_RDS          21      /* RDS sockets                  */
#define PPM_AF_SNA          22      /* Linux SNA Project (nutters!) */
#define PPM_AF_IRDA         23      /* IRDA sockets                 */
#define PPM_AF_PPPOX        24      /* PPPoX sockets                */
#define PPM_AF_WANPIPE      25      /* Wanpipe API Sockets */
#define PPM_AF_LLC          26      /* Linux LLC                    */
#define PPM_AF_CAN          29      /* Controller Area Network      */
#define PPM_AF_TIPC         30      /* TIPC sockets                 */
#define PPM_AF_BLUETOOTH    31      /* Bluetooth sockets            */
#define PPM_AF_IUCV         32      /* IUCV sockets                 */
#define PPM_AF_RXRPC        33      /* RxRPC sockets                */
#define PPM_AF_ISDN         34      /* mISDN sockets                */
#define PPM_AF_PHONET       35      /* Phonet sockets               */
#define PPM_AF_IEEE802154   36      /* IEEE802154 sockets           */
#define PPM_AF_CAIF         37      /* CAIF sockets                 */
#define PPM_AF_ALG          38      /* Algorithm sockets            */
#define PPM_AF_NFC          39      /* NFC sockets                  */

/*
 * File flags
 */
#define PPM_O_NONE	0
#define PPM_O_RDONLY	(1 << 0)	/* Open for reading only */
#define PPM_O_WRONLY	(1 << 1)	/* Open for writing only */
#define PPM_O_RDWR	(PPM_O_RDONLY | PPM_O_WRONLY)	/* Open for reading and writing */
#define PPM_O_CREAT	(1 << 2)	/* Create a new file if it doesn't exist. */
#define PPM_O_APPEND	(1 << 3)	/* If set, the file offset shall be set to the end of the file prior to each write. */
#define PPM_O_DSYNC	(1 << 4)
#define PPM_O_EXCL	(1 << 5)
#define PPM_O_NONBLOCK	(1 << 6)
#define PPM_O_SYNC	(1 << 7)
#define PPM_O_TRUNC	(1 << 8)
#define PPM_O_DIRECT	(1 << 9)
#define PPM_O_DIRECTORY (1 << 10)
#define PPM_O_LARGEFILE (1 << 11)
#define PPM_O_CLOEXEC	(1 << 12)

/*
 * File modes
 */
#define PPM_S_NONE  0
#define PPM_S_IXOTH (1 << 0)
#define PPM_S_IWOTH (1 << 1)
#define PPM_S_IROTH (1 << 2)
#define PPM_S_IXGRP (1 << 3)
#define PPM_S_IWGRP (1 << 4)
#define PPM_S_IRGRP (1 << 5)
#define PPM_S_IXUSR (1 << 6)
#define PPM_S_IWUSR (1 << 7)
#define PPM_S_IRUSR (1 << 8)
#define PPM_S_ISVTX (1 << 9)
#define PPM_S_ISGID (1 << 10)
#define PPM_S_ISUID (1 << 11)

/*
 * flock() flags
 */
#define PPM_LOCK_NONE 0
#define PPM_LOCK_SH (1 << 0)
#define PPM_LOCK_EX (1 << 1)
#define PPM_LOCK_NB (1 << 2)
#define PPM_LOCK_UN (1 << 3)

/*
 * Clone flags
 */
#define PPM_CL_NONE 0
#define PPM_CL_CLONE_FILES (1 << 0)
#define PPM_CL_CLONE_FS (1 << 1)
#define PPM_CL_CLONE_IO (1 << 2)
#define PPM_CL_CLONE_NEWIPC (1 << 3)
#define PPM_CL_CLONE_NEWNET (1 << 4)
#define PPM_CL_CLONE_NEWNS (1 << 5)
#define PPM_CL_CLONE_NEWPID (1 << 6)
#define PPM_CL_CLONE_NEWUTS (1 << 7)
#define PPM_CL_CLONE_PARENT (1 << 8)
#define PPM_CL_CLONE_PARENT_SETTID (1 << 9)
#define PPM_CL_CLONE_PTRACE (1 << 10)
#define PPM_CL_CLONE_SIGHAND (1 << 11)
#define PPM_CL_CLONE_SYSVSEM (1 << 12)
#define PPM_CL_CLONE_THREAD (1 << 13)
#define PPM_CL_CLONE_UNTRACED (1 << 14)
#define PPM_CL_CLONE_VM (1 << 15)
#define PPM_CL_CLONE_INVERTED (1 << 16)	/* libsinsp-specific flag. It's set if clone() returned in */
										/* the child process before than in the parent process. */
#define PPM_CL_NAME_CHANGED (1 << 17)	/* libsinsp-specific flag. Set when the thread name changes */
										/* (for example because execve was called) */
#define PPM_CL_CLOSED (1 << 18)			/* thread has been closed. */
#define PPM_CL_ACTIVE (1 << 19)			/* libsinsp-specific flag. Set in the first non-clone event for
										   this thread. */
#define PPM_CL_CLONE_NEWUSER (1 << 20)
#define PPM_CL_PIPE_SRC (1 << 21)			/* libsinsp-specific flag. Set if this thread has been
										       detected to be the source in a shell pipe. */
#define PPM_CL_PIPE_DST (1 << 22)			/* libsinsp-specific flag. Set if this thread has been
										       detected to be the destination in a shell pipe. */
#define PPM_CL_CLONE_CHILD_CLEARTID (1 << 23)
#define PPM_CL_CLONE_CHILD_SETTID (1 << 24)
#define PPM_CL_CLONE_SETTLS (1 << 25)
#define PPM_CL_CLONE_STOPPED (1 << 26)
#define PPM_CL_CLONE_VFORK (1 << 27)
#define PPM_CL_CLONE_NEWCGROUP (1 << 28)
#define PPM_CL_CHILD_IN_PIDNS (1<<29)			/* true if the thread created by clone() is *not*
									in the init pid namespace */

/*
 * Futex Operations
 */
#define PPM_FU_FUTEX_WAIT 0
#define PPM_FU_FUTEX_WAKE 1
#define PPM_FU_FUTEX_FD 2
#define PPM_FU_FUTEX_REQUEUE 3
#define PPM_FU_FUTEX_CMP_REQUEUE 4
#define PPM_FU_FUTEX_WAKE_OP 5
#define PPM_FU_FUTEX_LOCK_PI 6
#define PPM_FU_FUTEX_UNLOCK_PI 7
#define PPM_FU_FUTEX_TRYLOCK_PI 8
#define PPM_FU_FUTEX_WAIT_BITSET 9
#define PPM_FU_FUTEX_WAKE_BITSET 10
#define PPM_FU_FUTEX_WAIT_REQUEUE_PI 11
#define PPM_FU_FUTEX_CMP_REQUEUE_PI 12
#define PPM_FU_FUTEX_PRIVATE_FLAG	128
#define PPM_FU_FUTEX_CLOCK_REALTIME 256

/*
 * lseek() and llseek() whence
 */
#define PPM_SEEK_SET 0
#define PPM_SEEK_CUR 1
#define PPM_SEEK_END 2

/*
 * poll() flags
 */
#define PPM_POLLIN (1 << 0)
#define PPM_POLLPRI (1 << 1)
#define PPM_POLLOUT (1 << 2)
#define PPM_POLLRDHUP (1 << 3)
#define PPM_POLLERR (1 << 4)
#define PPM_POLLHUP (1 << 5)
#define PPM_POLLNVAL (1 << 6)
#define PPM_POLLRDNORM (1 << 7)
#define PPM_POLLRDBAND (1 << 8)
#define PPM_POLLWRNORM (1 << 9)
#define PPM_POLLWRBAND (1 << 10)

/*
 * mount() flags
 */
#define PPM_MS_RDONLY       (1<<0)
#define PPM_MS_NOSUID       (1<<1)
#define PPM_MS_NODEV        (1<<2)
#define PPM_MS_NOEXEC       (1<<3)
#define PPM_MS_SYNCHRONOUS  (1<<4)
#define PPM_MS_REMOUNT      (1<<5)
#define PPM_MS_MANDLOCK     (1<<6)
#define PPM_MS_DIRSYNC      (1<<7)

#define PPM_MS_NOATIME      (1<<10)
#define PPM_MS_NODIRATIME   (1<<11)
#define PPM_MS_BIND         (1<<12)
#define PPM_MS_MOVE         (1<<13)
#define PPM_MS_REC          (1<<14)
#define PPM_MS_SILENT       (1<<15)
#define PPM_MS_POSIXACL     (1<<16)
#define PPM_MS_UNBINDABLE   (1<<17)
#define PPM_MS_PRIVATE      (1<<18)
#define PPM_MS_SLAVE        (1<<19)
#define PPM_MS_SHARED       (1<<20)
#define PPM_MS_RELATIME     (1<<21)
#define PPM_MS_KERNMOUNT    (1<<22)
#define PPM_MS_I_VERSION    (1<<23)
#define PPM_MS_STRICTATIME  (1<<24)
#define PPM_MS_LAZYTIME     (1<<25)

#define PPM_MS_NOSEC        (1<<28)
#define PPM_MS_BORN         (1<<29)
#define PPM_MS_ACTIVE       (1<<30)
#define PPM_MS_NOUSER       (1<<31)

/*
 * umount() flags
 */
#define PPM_MNT_FORCE       1
#define PPM_MNT_DETACH      2
#define PPM_MNT_EXPIRE      4
#define PPM_UMOUNT_NOFOLLOW 8

/*
 * shutdown() how
 */
#define PPM_SHUT_RD 0
#define PPM_SHUT_WR 1
#define PPM_SHUT_RDWR 2

/*
 * fs *at() flags
 */
#define PPM_AT_FDCWD -100

/*
 * unlinkat() flags
 */
#define PPM_AT_REMOVEDIR 0x200

/*
 * linkat() flags
 */
#define PPM_AT_SYMLINK_FOLLOW	0x400
#define PPM_AT_EMPTY_PATH       0x1000

/*
 * rlimit resources
 */
#define PPM_RLIMIT_CPU 0 /* CPU time in sec */
#define PPM_RLIMIT_FSIZE 1 /* Maximum filesize */
#define PPM_RLIMIT_DATA 2 /* max data size */
#define PPM_RLIMIT_STACK 3 /* max stack size */
#define PPM_RLIMIT_CORE 4 /* max core file size */
#define PPM_RLIMIT_RSS 5 /* max resident set size */
#define PPM_RLIMIT_NPROC 6 /* max number of processes */
#define PPM_RLIMIT_NOFILE 7 /* max number of open files */
#define PPM_RLIMIT_MEMLOCK 8 /* max locked-in-memory address space */
#define PPM_RLIMIT_AS 9 /* address space limit */
#define PPM_RLIMIT_LOCKS 10  /* maximum file locks held */
#define PPM_RLIMIT_SIGPENDING 11 /* max number of pending signals */
#define PPM_RLIMIT_MSGQUEUE 12 /* maximum bytes in POSIX mqueues */
#define PPM_RLIMIT_NICE 13 /* max nice prio allowed to raise to 0-39 for nice level 19 .. -20 */
#define PPM_RLIMIT_RTPRIO 14 /* maximum realtime priority */
#define PPM_RLIMIT_RTTIME 15 /* timeout for RT tasks in us */
#define PPM_RLIMIT_UNKNOWN 255 /* CPU time in sec */

/*
 * fcntl commands
 */
#define PPM_FCNTL_UNKNOWN 0
#define PPM_FCNTL_F_DUPFD 1
#define PPM_FCNTL_F_GETFD 2
#define PPM_FCNTL_F_SETFD 3
#define PPM_FCNTL_F_GETFL 4
#define PPM_FCNTL_F_SETFL 5
#define PPM_FCNTL_F_GETLK 6
#define PPM_FCNTL_F_SETLK 8
#define PPM_FCNTL_F_SETLKW 9
#define PPM_FCNTL_F_SETOWN 10
#define PPM_FCNTL_F_GETOWN 12
#define PPM_FCNTL_F_SETSIG 13
#define PPM_FCNTL_F_GETSIG 15
#ifndef CONFIG_64BIT
#define PPM_FCNTL_F_GETLK64 17
#define PPM_FCNTL_F_SETLK64 18
#define PPM_FCNTL_F_SETLKW64 19
#endif
#define PPM_FCNTL_F_SETOWN_EX 21
#define PPM_FCNTL_F_GETOWN_EX 22
#define PPM_FCNTL_F_SETLEASE 23
#define PPM_FCNTL_F_GETLEASE 24
#define PPM_FCNTL_F_CANCELLK 25
#define PPM_FCNTL_F_DUPFD_CLOEXEC 26
#define PPM_FCNTL_F_NOTIFY 27
#define PPM_FCNTL_F_SETPIPE_SZ 28
#define PPM_FCNTL_F_GETPIPE_SZ 29
#define PPM_FCNTL_F_OFD_GETLK 30
#define PPM_FCNTL_F_OFD_SETLK 31
#define PPM_FCNTL_F_OFD_SETLKW 32

/*
 * getsockopt/setsockopt levels
 */
#define PPM_SOCKOPT_LEVEL_UNKNOWN 0
#define PPM_SOCKOPT_LEVEL_SOL_SOCKET 1
#define PPM_SOCKOPT_LEVEL_SOL_TCP 2

/*
 * getsockopt/setsockopt options
 * SOL_SOCKET only currently
 */
#define PPM_SOCKOPT_UNKNOWN	0
#define PPM_SOCKOPT_SO_DEBUG	1
#define PPM_SOCKOPT_SO_REUSEADDR	2
#define PPM_SOCKOPT_SO_TYPE		3
#define PPM_SOCKOPT_SO_ERROR	4
#define PPM_SOCKOPT_SO_DONTROUTE	5
#define PPM_SOCKOPT_SO_BROADCAST	6
#define PPM_SOCKOPT_SO_SNDBUF	7
#define PPM_SOCKOPT_SO_RCVBUF	8
#define PPM_SOCKOPT_SO_SNDBUFFORCE	32
#define PPM_SOCKOPT_SO_RCVBUFFORCE	33
#define PPM_SOCKOPT_SO_KEEPALIVE	9
#define PPM_SOCKOPT_SO_OOBINLINE	10
#define PPM_SOCKOPT_SO_NO_CHECK	11
#define PPM_SOCKOPT_SO_PRIORITY	12
#define PPM_SOCKOPT_SO_LINGER	13
#define PPM_SOCKOPT_SO_BSDCOMPAT	14
#define PPM_SOCKOPT_SO_REUSEPORT	15
#define PPM_SOCKOPT_SO_PASSCRED	16
#define PPM_SOCKOPT_SO_PEERCRED	17
#define PPM_SOCKOPT_SO_RCVLOWAT	18
#define PPM_SOCKOPT_SO_SNDLOWAT	19
#define PPM_SOCKOPT_SO_RCVTIMEO	20
#define PPM_SOCKOPT_SO_SNDTIMEO	21
#define PPM_SOCKOPT_SO_SECURITY_AUTHENTICATION		22
#define PPM_SOCKOPT_SO_SECURITY_ENCRYPTION_TRANSPORT	23
#define PPM_SOCKOPT_SO_SECURITY_ENCRYPTION_NETWORK		24
#define PPM_SOCKOPT_SO_BINDTODEVICE	25
#define PPM_SOCKOPT_SO_ATTACH_FILTER	26
#define PPM_SOCKOPT_SO_DETACH_FILTER	27
#define PPM_SOCKOPT_SO_PEERNAME		28
#define PPM_SOCKOPT_SO_TIMESTAMP		29
#define PPM_SOCKOPT_SO_ACCEPTCONN		30
#define PPM_SOCKOPT_SO_PEERSEC		31
#define PPM_SOCKOPT_SO_PASSSEC		34
#define PPM_SOCKOPT_SO_TIMESTAMPNS		35
#define PPM_SOCKOPT_SO_MARK			36
#define PPM_SOCKOPT_SO_TIMESTAMPING		37
#define PPM_SOCKOPT_SO_PROTOCOL		38
#define PPM_SOCKOPT_SO_DOMAIN		39
#define PPM_SOCKOPT_SO_RXQ_OVFL             40
#define PPM_SOCKOPT_SO_WIFI_STATUS		41
#define PPM_SOCKOPT_SO_PEEK_OFF		42
#define PPM_SOCKOPT_SO_NOFCS		43
#define PPM_SOCKOPT_SO_LOCK_FILTER		44
#define PPM_SOCKOPT_SO_SELECT_ERR_QUEUE	45
#define PPM_SOCKOPT_SO_BUSY_POLL		46
#define PPM_SOCKOPT_SO_MAX_PACING_RATE	47
#define PPM_SOCKOPT_SO_BPF_EXTENSIONS	48
#define PPM_SOCKOPT_SO_INCOMING_CPU		49
#define PPM_SOCKOPT_SO_ATTACH_BPF		50
#define PPM_SOCKOPT_SO_PEERGROUPS		51
#define PPM_SOCKOPT_SO_MEMINFO		52
#define PPM_SOCKOPT_SO_COOKIE		53

/*
 * getsockopt/setsockopt dynamic params
 */
#define PPM_SOCKOPT_IDX_UNKNOWN 0
#define PPM_SOCKOPT_IDX_ERRNO 1
#define PPM_SOCKOPT_IDX_UINT32 2
#define PPM_SOCKOPT_IDX_UINT64 3
#define PPM_SOCKOPT_IDX_TIMEVAL 4
#define PPM_SOCKOPT_IDX_MAX 5

 /*
 * ptrace requests
 */
#define PPM_PTRACE_UNKNOWN 0
#define PPM_PTRACE_TRACEME 1
#define PPM_PTRACE_PEEKTEXT 2
#define PPM_PTRACE_PEEKDATA 3
#define PPM_PTRACE_PEEKUSR 4
#define PPM_PTRACE_POKETEXT 5
#define PPM_PTRACE_POKEDATA 6
#define PPM_PTRACE_POKEUSR 7
#define PPM_PTRACE_CONT 8
#define PPM_PTRACE_KILL 9
#define PPM_PTRACE_SINGLESTEP 10
#define PPM_PTRACE_ATTACH 11
#define PPM_PTRACE_DETACH 12
#define PPM_PTRACE_SYSCALL 13
#define PPM_PTRACE_SETOPTIONS 14
#define PPM_PTRACE_GETEVENTMSG 15
#define PPM_PTRACE_GETSIGINFO 16
#define PPM_PTRACE_SETSIGINFO 17
#define PPM_PTRACE_GETREGSET 18
#define PPM_PTRACE_SETREGSET 19
#define PPM_PTRACE_SEIZE 20
#define PPM_PTRACE_INTERRUPT 21
#define PPM_PTRACE_LISTEN 22
#define PPM_PTRACE_PEEKSIGINFO 23
#define PPM_PTRACE_GETSIGMASK 24
#define PPM_PTRACE_SETSIGMASK 25
#define PPM_PTRACE_GETREGS 26
#define PPM_PTRACE_SETREGS 27
#define PPM_PTRACE_GETFPREGS 28
#define PPM_PTRACE_SETFPREGS 29
#define PPM_PTRACE_GETFPXREGS 30
#define PPM_PTRACE_SETFPXREGS 31
#define PPM_PTRACE_OLDSETOPTIONS 32
#define PPM_PTRACE_GET_THREAD_AREA 33
#define PPM_PTRACE_SET_THREAD_AREA 34
#define PPM_PTRACE_ARCH_PRCTL 35
#define PPM_PTRACE_SYSEMU 36
#define PPM_PTRACE_SYSEMU_SINGLESTEP 37
#define PPM_PTRACE_SINGLEBLOCK 38

/*
 * ptrace dynamic table indexes
 */
#define PPM_PTRACE_IDX_UINT64 0
#define PPM_PTRACE_IDX_SIGTYPE 1

#define PPM_PTRACE_IDX_MAX 2

#define PPM_BPF_IDX_FD 0
#define PPM_BPF_IDX_RES 1

#define PPM_BPF_IDX_MAX 2

/*
 * memory protection flags
 */
#define PPM_PROT_NONE		0
#define PPM_PROT_READ		(1 << 0)
#define PPM_PROT_WRITE		(1 << 1)
#define PPM_PROT_EXEC		(1 << 2)
#define PPM_PROT_SEM		(1 << 3)
#define PPM_PROT_GROWSDOWN	(1 << 4)
#define PPM_PROT_GROWSUP	(1 << 5)
#define PPM_PROT_SAO		(1 << 6)

/*
 * mmap flags
 */
#define PPM_MAP_SHARED		(1 << 0)
#define PPM_MAP_PRIVATE		(1 << 1)
#define PPM_MAP_FIXED		(1 << 2)
#define PPM_MAP_ANONYMOUS	(1 << 3)
#define PPM_MAP_32BIT		(1 << 4)
#define PPM_MAP_RENAME		(1 << 5)
#define PPM_MAP_NORESERVE	(1 << 6)
#define PPM_MAP_POPULATE	(1 << 7)
#define PPM_MAP_NONBLOCK	(1 << 8)
#define PPM_MAP_GROWSDOWN	(1 << 9)
#define PPM_MAP_DENYWRITE	(1 << 10)
#define PPM_MAP_EXECUTABLE	(1 << 11)
#define PPM_MAP_INHERIT		(1 << 12)
#define PPM_MAP_FILE		(1 << 13)
#define PPM_MAP_LOCKED		(1 << 14)

/*
 * splice flags
 */
#define PPM_SPLICE_F_MOVE		(1 << 0)
#define PPM_SPLICE_F_NONBLOCK	(1 << 1)
#define PPM_SPLICE_F_MORE		(1 << 2)
#define PPM_SPLICE_F_GIFT		(1 << 3)

/*
 * quotactl cmds
 */
#define PPM_Q_QUOTAON		(1 << 0)
#define PPM_Q_QUOTAOFF		(1 << 1)
#define PPM_Q_GETFMT		(1 << 2)
#define PPM_Q_GETINFO		(1 << 3)
#define PPM_Q_SETINFO		(1 << 4)
#define PPM_Q_GETQUOTA		(1 << 5)
#define PPM_Q_SETQUOTA		(1 << 6)
#define PPM_Q_SYNC			(1 << 7)
#define PPM_Q_XQUOTAON		(1 << 8)
#define PPM_Q_XQUOTAOFF		(1 << 9)
#define PPM_Q_XGETQUOTA		(1 << 10)
#define PPM_Q_XSETQLIM		(1 << 11)
#define PPM_Q_XGETQSTAT		(1 << 12)
#define PPM_Q_XQUOTARM		(1 << 13)
#define PPM_Q_XQUOTASYNC	(1 << 14)
#define PPM_Q_XGETQSTATV	(1 << 15)

/*
 * quotactl types
 */
#define PPM_USRQUOTA		(1 << 0)
#define PPM_GRPQUOTA		(1 << 1)

/*
 * quotactl dqi_flags
 */
#define PPM_DQF_NONE		(1 << 0)
#define PPM_V1_DQF_RSQUASH	(1 << 1)

/*
 * quotactl quotafmts
 */
#define PPM_QFMT_NOT_USED		(1 << 0)
#define PPM_QFMT_VFS_OLD	(1 << 1)
#define PPM_QFMT_VFS_V0		(1 << 2)
#define PPM_QFMT_VFS_V1		(1 << 3)

/*
 * Semop flags
 */
#define PPM_IPC_NOWAIT		(1 << 0)
#define PPM_SEM_UNDO		(1 << 1)

/*
 * Semget flags
 */
#define PPM_IPC_CREAT  (1 << 13)
#define PPM_IPC_EXCL   (1 << 14)

#define PPM_IPC_STAT		(1 << 0)
#define PPM_IPC_SET		(1 << 1)
#define PPM_IPC_RMID		(1 << 2)
#define PPM_IPC_INFO		(1 << 3)
#define PPM_SEM_INFO		(1 << 4)
#define PPM_SEM_STAT		(1 << 5)
#define PPM_GETALL		(1 << 6)
#define PPM_GETNCNT		(1 << 7)
#define PPM_GETPID		(1 << 8)
#define PPM_GETVAL		(1 << 9)
#define PPM_GETZCNT		(1 << 10)
#define PPM_SETALL		(1 << 11)
#define PPM_SETVAL		(1 << 12)

/*
 * Access flags
 */
#define PPM_F_OK            (0)
#define PPM_X_OK            (1 << 0)
#define PPM_W_OK            (1 << 1)
#define PPM_R_OK            (1 << 2)

/*
 * Page fault flags
 */
#define PPM_PF_PROTECTION_VIOLATION	(1 << 0)
#define PPM_PF_PAGE_NOT_PRESENT		(1 << 1)
#define PPM_PF_WRITE_ACCESS		(1 << 2)
#define PPM_PF_READ_ACCESS		(1 << 3)
#define PPM_PF_USER_FAULT		(1 << 4)
#define PPM_PF_SUPERVISOR_FAULT		(1 << 5)
#define PPM_PF_RESERVED_PAGE		(1 << 6)
#define PPM_PF_INSTRUCTION_FETCH	(1 << 7)

/*
 * SuS says limits have to be unsigned.
 * Which makes a ton more sense anyway.
 *
 * Some architectures override this (for compatibility reasons):
 */
#ifndef RLIM_INFINITY
# define RLIM_INFINITY          (~0UL)
#endif

/*
 * RLIMIT_STACK default maximum - some architectures override it:
 */
#ifndef _STK_LIM_MAX
# define _STK_LIM_MAX           RLIM_INFINITY
#endif

/*
 * The list of event types
 * Enter events have even numbers while exit events have odd numbers.
 * NOTE: there can't be gaps in the numbering, because these numbers correspond
 * to the entries in the g_event_info table
 */
#define PPME_DIRECTION_FLAG 1
#define PPME_IS_ENTER(x) ((x & PPME_DIRECTION_FLAG) == 0)
#define PPME_IS_EXIT(x) (x & PPME_DIRECTION_FLAG)
#define PPME_MAKE_ENTER(x) (x & (~1))

/*
 * Event category to classify events in generic categories
 */
enum ppm_capture_category {
	PPMC_NONE = 0,
	PPMC_SYSCALL = 1,
	PPMC_CONTEXT_SWITCH = 2,
	PPMC_SIGNAL = 3,
	PPMC_PAGE_FAULT = 4,
};

/** @defgroup etypes Event Types
 *  @{
 */
enum ppm_event_type {
	PPME_GENERIC_E = 0,
	PPME_GENERIC_X = 1,
	PPME_SYSCALL_OPEN_E = 2,
	PPME_SYSCALL_OPEN_X = 3,
	PPME_SYSCALL_CLOSE_E = 4,
	PPME_SYSCALL_CLOSE_X = 5,
	PPME_SYSCALL_READ_E = 6,
	PPME_SYSCALL_READ_X = 7,
	PPME_SYSCALL_WRITE_E = 8,
	PPME_SYSCALL_WRITE_X = 9,
	PPME_SYSCALL_BRK_1_E = 10,
	PPME_SYSCALL_BRK_1_X = 11,
	PPME_SYSCALL_EXECVE_8_E = 12,
	PPME_SYSCALL_EXECVE_8_X = 13,
	PPME_SYSCALL_CLONE_11_E = 14,
	PPME_SYSCALL_CLONE_11_X = 15,
	PPME_PROCEXIT_E = 16,
	PPME_PROCEXIT_X = 17,	/* This should never be called */
	PPME_SOCKET_SOCKET_E = 18,
	PPME_SOCKET_SOCKET_X = 19,
	PPME_SOCKET_BIND_E = 20,
	PPME_SOCKET_BIND_X = 21,
	PPME_SOCKET_CONNECT_E = 22,
	PPME_SOCKET_CONNECT_X = 23,
	PPME_SOCKET_LISTEN_E = 24,
	PPME_SOCKET_LISTEN_X = 25,
	PPME_SOCKET_ACCEPT_E = 26,
	PPME_SOCKET_ACCEPT_X = 27,
	PPME_SOCKET_SEND_E = 28,
	PPME_SOCKET_SEND_X = 29,
	PPME_SOCKET_SENDTO_E = 30,
	PPME_SOCKET_SENDTO_X = 31,
	PPME_SOCKET_RECV_E = 32,
	PPME_SOCKET_RECV_X = 33,
	PPME_SOCKET_RECVFROM_E = 34,
	PPME_SOCKET_RECVFROM_X = 35,
	PPME_SOCKET_SHUTDOWN_E = 36,
	PPME_SOCKET_SHUTDOWN_X = 37,
	PPME_SOCKET_GETSOCKNAME_E = 38,
	PPME_SOCKET_GETSOCKNAME_X = 39,
	PPME_SOCKET_GETPEERNAME_E = 40,
	PPME_SOCKET_GETPEERNAME_X = 41,
	PPME_SOCKET_SOCKETPAIR_E = 42,
	PPME_SOCKET_SOCKETPAIR_X = 43,
	PPME_SOCKET_SETSOCKOPT_E = 44,
	PPME_SOCKET_SETSOCKOPT_X = 45,
	PPME_SOCKET_GETSOCKOPT_E = 46,
	PPME_SOCKET_GETSOCKOPT_X = 47,
	PPME_SOCKET_SENDMSG_E = 48,
	PPME_SOCKET_SENDMSG_X = 49,
	PPME_SOCKET_SENDMMSG_E = 50,
	PPME_SOCKET_SENDMMSG_X = 51,
	PPME_SOCKET_RECVMSG_E = 52,
	PPME_SOCKET_RECVMSG_X = 53,
	PPME_SOCKET_RECVMMSG_E = 54,
	PPME_SOCKET_RECVMMSG_X = 55,
	PPME_SOCKET_ACCEPT4_E = 56,
	PPME_SOCKET_ACCEPT4_X = 57,
	PPME_SYSCALL_CREAT_E = 58,
	PPME_SYSCALL_CREAT_X = 59,
	PPME_SYSCALL_PIPE_E = 60,
	PPME_SYSCALL_PIPE_X = 61,
	PPME_SYSCALL_EVENTFD_E = 62,
	PPME_SYSCALL_EVENTFD_X = 63,
	PPME_SYSCALL_FUTEX_E = 64,
	PPME_SYSCALL_FUTEX_X = 65,
	PPME_SYSCALL_STAT_E = 66,
	PPME_SYSCALL_STAT_X = 67,
	PPME_SYSCALL_LSTAT_E = 68,
	PPME_SYSCALL_LSTAT_X = 69,
	PPME_SYSCALL_FSTAT_E = 70,
	PPME_SYSCALL_FSTAT_X = 71,
	PPME_SYSCALL_STAT64_E = 72,
	PPME_SYSCALL_STAT64_X = 73,
	PPME_SYSCALL_LSTAT64_E = 74,
	PPME_SYSCALL_LSTAT64_X = 75,
	PPME_SYSCALL_FSTAT64_E = 76,
	PPME_SYSCALL_FSTAT64_X = 77,
	PPME_SYSCALL_EPOLLWAIT_E = 78,
	PPME_SYSCALL_EPOLLWAIT_X = 79,
	PPME_SYSCALL_POLL_E = 80,
	PPME_SYSCALL_POLL_X = 81,
	PPME_SYSCALL_SELECT_E = 82,
	PPME_SYSCALL_SELECT_X = 83,
	PPME_SYSCALL_NEWSELECT_E = 84,
	PPME_SYSCALL_NEWSELECT_X = 85,
	PPME_SYSCALL_LSEEK_E = 86,
	PPME_SYSCALL_LSEEK_X = 87,
	PPME_SYSCALL_LLSEEK_E = 88,
	PPME_SYSCALL_LLSEEK_X = 89,
	PPME_SYSCALL_IOCTL_2_E = 90,
	PPME_SYSCALL_IOCTL_2_X = 91,
	PPME_SYSCALL_GETCWD_E = 92,
	PPME_SYSCALL_GETCWD_X = 93,
	PPME_SYSCALL_CHDIR_E = 94,
	PPME_SYSCALL_CHDIR_X = 95,
	PPME_SYSCALL_FCHDIR_E = 96,
	PPME_SYSCALL_FCHDIR_X = 97,
	/* mkdir/rmdir events are not emitted anymore */
	PPME_SYSCALL_MKDIR_E = 98,
	PPME_SYSCALL_MKDIR_X = 99,
	PPME_SYSCALL_RMDIR_E = 100,
	PPME_SYSCALL_RMDIR_X = 101,
	PPME_SYSCALL_OPENAT_E = 102,
	PPME_SYSCALL_OPENAT_X = 103,
	PPME_SYSCALL_LINK_E = 104,
	PPME_SYSCALL_LINK_X = 105,
	PPME_SYSCALL_LINKAT_E = 106,
	PPME_SYSCALL_LINKAT_X = 107,
	PPME_SYSCALL_UNLINK_E = 108,
	PPME_SYSCALL_UNLINK_X = 109,
	PPME_SYSCALL_UNLINKAT_E = 110,
	PPME_SYSCALL_UNLINKAT_X = 111,
	PPME_SYSCALL_PREAD_E = 112,
	PPME_SYSCALL_PREAD_X = 113,
	PPME_SYSCALL_PWRITE_E = 114,
	PPME_SYSCALL_PWRITE_X = 115,
	PPME_SYSCALL_READV_E = 116,
	PPME_SYSCALL_READV_X = 117,
	PPME_SYSCALL_WRITEV_E = 118,
	PPME_SYSCALL_WRITEV_X = 119,
	PPME_SYSCALL_PREADV_E = 120,
	PPME_SYSCALL_PREADV_X = 121,
	PPME_SYSCALL_PWRITEV_E = 122,
	PPME_SYSCALL_PWRITEV_X = 123,
	PPME_SYSCALL_DUP_E = 124,
	PPME_SYSCALL_DUP_X = 125,
	PPME_SYSCALL_SIGNALFD_E = 126,
	PPME_SYSCALL_SIGNALFD_X = 127,
	PPME_SYSCALL_KILL_E = 128,
	PPME_SYSCALL_KILL_X = 129,
	PPME_SYSCALL_TKILL_E = 130,
	PPME_SYSCALL_TKILL_X = 131,
	PPME_SYSCALL_TGKILL_E = 132,
	PPME_SYSCALL_TGKILL_X = 133,
	PPME_SYSCALL_NANOSLEEP_E = 134,
	PPME_SYSCALL_NANOSLEEP_X = 135,
	PPME_SYSCALL_TIMERFD_CREATE_E = 136,
	PPME_SYSCALL_TIMERFD_CREATE_X = 137,
	PPME_SYSCALL_INOTIFY_INIT_E = 138,
	PPME_SYSCALL_INOTIFY_INIT_X = 139,
	PPME_SYSCALL_GETRLIMIT_E = 140,
	PPME_SYSCALL_GETRLIMIT_X = 141,
	PPME_SYSCALL_SETRLIMIT_E = 142,
	PPME_SYSCALL_SETRLIMIT_X = 143,
	PPME_SYSCALL_PRLIMIT_E = 144,
	PPME_SYSCALL_PRLIMIT_X = 145,
	PPME_SCHEDSWITCH_1_E = 146,
	PPME_SCHEDSWITCH_1_X = 147,	/* This should never be called */
	PPME_DROP_E = 148,  /* For internal use */
	PPME_DROP_X = 149,	/* For internal use */
	PPME_SYSCALL_FCNTL_E = 150,  /* For internal use */
	PPME_SYSCALL_FCNTL_X = 151,	/* For internal use */
	PPME_SCHEDSWITCH_6_E = 152,
	PPME_SCHEDSWITCH_6_X = 153,	/* This should never be called */
	PPME_SYSCALL_EXECVE_13_E = 154,
	PPME_SYSCALL_EXECVE_13_X = 155,
	PPME_SYSCALL_CLONE_16_E = 156,
	PPME_SYSCALL_CLONE_16_X = 157,
	PPME_SYSCALL_BRK_4_E = 158,
	PPME_SYSCALL_BRK_4_X = 159,
	PPME_SYSCALL_MMAP_E = 160,
	PPME_SYSCALL_MMAP_X = 161,
	PPME_SYSCALL_MMAP2_E = 162,
	PPME_SYSCALL_MMAP2_X = 163,
	PPME_SYSCALL_MUNMAP_E = 164,
	PPME_SYSCALL_MUNMAP_X = 165,
	PPME_SYSCALL_SPLICE_E = 166,
	PPME_SYSCALL_SPLICE_X = 167,
	PPME_SYSCALL_PTRACE_E = 168,
	PPME_SYSCALL_PTRACE_X = 169,
	PPME_SYSCALL_IOCTL_3_E = 170,
	PPME_SYSCALL_IOCTL_3_X = 171,
	PPME_SYSCALL_EXECVE_14_E = 172,
	PPME_SYSCALL_EXECVE_14_X = 173,
	PPME_SYSCALL_RENAME_E = 174,
	PPME_SYSCALL_RENAME_X = 175,
	PPME_SYSCALL_RENAMEAT_E = 176,
	PPME_SYSCALL_RENAMEAT_X = 177,
	PPME_SYSCALL_SYMLINK_E = 178,
	PPME_SYSCALL_SYMLINK_X = 179,
	PPME_SYSCALL_SYMLINKAT_E = 180,
	PPME_SYSCALL_SYMLINKAT_X = 181,
	PPME_SYSCALL_FORK_E = 182,
	PPME_SYSCALL_FORK_X = 183,
	PPME_SYSCALL_VFORK_E = 184,
	PPME_SYSCALL_VFORK_X = 185,
	PPME_PROCEXIT_1_E = 186,
	PPME_PROCEXIT_1_X = 187,	/* This should never be called */
	PPME_SYSCALL_SENDFILE_E = 188,
	PPME_SYSCALL_SENDFILE_X = 189,	/* This should never be called */
	PPME_SYSCALL_QUOTACTL_E = 190,
	PPME_SYSCALL_QUOTACTL_X = 191,
	PPME_SYSCALL_SETRESUID_E = 192,
	PPME_SYSCALL_SETRESUID_X = 193,
	PPME_SYSCALL_SETRESGID_E = 194,
	PPME_SYSCALL_SETRESGID_X = 195,
	PPME_SYSDIGEVENT_E = 196,
	PPME_SYSDIGEVENT_X = 197, /* This should never be called */
	PPME_SYSCALL_SETUID_E = 198,
	PPME_SYSCALL_SETUID_X = 199,
	PPME_SYSCALL_SETGID_E = 200,
	PPME_SYSCALL_SETGID_X = 201,
	PPME_SYSCALL_GETUID_E = 202,
	PPME_SYSCALL_GETUID_X = 203,
	PPME_SYSCALL_GETEUID_E = 204,
	PPME_SYSCALL_GETEUID_X = 205,
	PPME_SYSCALL_GETGID_E = 206,
	PPME_SYSCALL_GETGID_X = 207,
	PPME_SYSCALL_GETEGID_E = 208,
	PPME_SYSCALL_GETEGID_X = 209,
	PPME_SYSCALL_GETRESUID_E = 210,
	PPME_SYSCALL_GETRESUID_X = 211,
	PPME_SYSCALL_GETRESGID_E = 212,
	PPME_SYSCALL_GETRESGID_X = 213,
	PPME_SYSCALL_EXECVE_15_E = 214,
	PPME_SYSCALL_EXECVE_15_X = 215,
	PPME_SYSCALL_CLONE_17_E = 216,
	PPME_SYSCALL_CLONE_17_X = 217,
	PPME_SYSCALL_FORK_17_E = 218,
	PPME_SYSCALL_FORK_17_X = 219,
	PPME_SYSCALL_VFORK_17_E = 220,
	PPME_SYSCALL_VFORK_17_X = 221,
	PPME_SYSCALL_CLONE_20_E = 222,
	PPME_SYSCALL_CLONE_20_X = 223,
	PPME_SYSCALL_FORK_20_E = 224,
	PPME_SYSCALL_FORK_20_X = 225,
	PPME_SYSCALL_VFORK_20_E = 226,
	PPME_SYSCALL_VFORK_20_X = 227,
	PPME_CONTAINER_E = 228,
	PPME_CONTAINER_X = 229,
	PPME_SYSCALL_EXECVE_16_E = 230,
	PPME_SYSCALL_EXECVE_16_X = 231,
	PPME_SIGNALDELIVER_E = 232,
	PPME_SIGNALDELIVER_X = 233, /* This should never be called */
	PPME_PROCINFO_E = 234,
	PPME_PROCINFO_X = 235,	/* This should never be called */
	PPME_SYSCALL_GETDENTS_E = 236,
	PPME_SYSCALL_GETDENTS_X = 237,
	PPME_SYSCALL_GETDENTS64_E = 238,
	PPME_SYSCALL_GETDENTS64_X = 239,
	PPME_SYSCALL_SETNS_E = 240,
	PPME_SYSCALL_SETNS_X = 241,
	PPME_SYSCALL_FLOCK_E = 242,
	PPME_SYSCALL_FLOCK_X = 243,
	PPME_CPU_HOTPLUG_E = 244,
	PPME_CPU_HOTPLUG_X = 245, /* This should never be called */
	PPME_SOCKET_ACCEPT_5_E = 246,
	PPME_SOCKET_ACCEPT_5_X = 247,
	PPME_SOCKET_ACCEPT4_5_E = 248,
	PPME_SOCKET_ACCEPT4_5_X = 249,
	PPME_SYSCALL_SEMOP_E = 250,
	PPME_SYSCALL_SEMOP_X = 251,
	PPME_SYSCALL_SEMCTL_E = 252,
	PPME_SYSCALL_SEMCTL_X = 253,
	PPME_SYSCALL_PPOLL_E = 254,
	PPME_SYSCALL_PPOLL_X = 255,
	PPME_SYSCALL_MOUNT_E = 256,
	PPME_SYSCALL_MOUNT_X = 257,
	PPME_SYSCALL_UMOUNT_E = 258,
	PPME_SYSCALL_UMOUNT_X = 259,
	PPME_K8S_E = 260,
	PPME_K8S_X = 261,
	PPME_SYSCALL_SEMGET_E = 262,
	PPME_SYSCALL_SEMGET_X = 263,
	PPME_SYSCALL_ACCESS_E = 264,
	PPME_SYSCALL_ACCESS_X = 265,
	PPME_SYSCALL_CHROOT_E = 266,
	PPME_SYSCALL_CHROOT_X = 267,
	PPME_TRACER_E = 268,
	PPME_TRACER_X = 269,
	PPME_MESOS_E = 270,
	PPME_MESOS_X = 271,
	PPME_CONTAINER_JSON_E = 272,
	PPME_CONTAINER_JSON_X = 273,
	PPME_SYSCALL_SETSID_E = 274,
	PPME_SYSCALL_SETSID_X = 275,
	PPME_SYSCALL_MKDIR_2_E = 276,
	PPME_SYSCALL_MKDIR_2_X = 277,
	PPME_SYSCALL_RMDIR_2_E = 278,
	PPME_SYSCALL_RMDIR_2_X = 279,
	PPME_NOTIFICATION_E = 280,
	PPME_NOTIFICATION_X = 281,
	PPME_SYSCALL_EXECVE_17_E = 282,
	PPME_SYSCALL_EXECVE_17_X = 283,
	PPME_SYSCALL_UNSHARE_E = 284,
	PPME_SYSCALL_UNSHARE_X = 285,
	PPME_INFRASTRUCTURE_EVENT_E = 286,
	PPME_INFRASTRUCTURE_EVENT_X = 287,
	PPME_SYSCALL_EXECVE_18_E = 288,
	PPME_SYSCALL_EXECVE_18_X = 289,
	PPME_PAGE_FAULT_E = 290,
	PPME_PAGE_FAULT_X = 291,
	PPME_SYSCALL_EXECVE_19_E = 292,
	PPME_SYSCALL_EXECVE_19_X = 293,
	PPME_SYSCALL_SETPGID_E = 294,
	PPME_SYSCALL_SETPGID_X = 295,
	PPME_SYSCALL_BPF_E = 296,
	PPME_SYSCALL_BPF_X = 297,
	PPME_SYSCALL_SECCOMP_E = 298,
	PPME_SYSCALL_SECCOMP_X = 299,
	PPME_SYSCALL_UNLINK_2_E = 300,
	PPME_SYSCALL_UNLINK_2_X = 301,
	PPME_SYSCALL_UNLINKAT_2_E = 302,
	PPME_SYSCALL_UNLINKAT_2_X = 303,
	PPME_SYSCALL_MKDIRAT_E = 304,
	PPME_SYSCALL_MKDIRAT_X = 305,
	PPME_SYSCALL_OPENAT_2_E = 306,
	PPME_SYSCALL_OPENAT_2_X = 307,
	PPME_SYSCALL_LINK_2_E = 308,
	PPME_SYSCALL_LINK_2_X = 309,
	PPME_SYSCALL_LINKAT_2_E = 310,
	PPME_SYSCALL_LINKAT_2_X = 311,
	PPME_SYSCALL_FCHMODAT_E = 312,
	PPME_SYSCALL_FCHMODAT_X = 313,
	PPME_SYSCALL_CHMOD_E = 314,
	PPME_SYSCALL_CHMOD_X = 315,
	PPME_SYSCALL_FCHMOD_E = 316,
	PPME_SYSCALL_FCHMOD_X = 317,
	PPM_EVENT_MAX = 318
};
/*@}*/

/*
 * System-independent syscall codes
 */
enum ppm_syscall_code {
	PPM_SC_UNKNOWN = 0,
	PPM_SC_RESTART_SYSCALL = 1,
	PPM_SC_EXIT = 2,
	PPM_SC_READ = 3,
	PPM_SC_WRITE = 4,
	PPM_SC_OPEN = 5,
	PPM_SC_CLOSE = 6,
	PPM_SC_CREAT = 7,
	PPM_SC_LINK = 8,
	PPM_SC_UNLINK = 9,
	PPM_SC_CHDIR = 10,
	PPM_SC_TIME = 11,
	PPM_SC_MKNOD = 12,
	PPM_SC_CHMOD = 13,
	PPM_SC_STAT = 14,
	PPM_SC_LSEEK = 15,
	PPM_SC_GETPID = 16,
	PPM_SC_MOUNT = 17,
	PPM_SC_PTRACE = 18,
	PPM_SC_ALARM = 19,
	PPM_SC_FSTAT = 20,
	PPM_SC_PAUSE = 21,
	PPM_SC_UTIME = 22,
	PPM_SC_ACCESS = 23,
	PPM_SC_SYNC = 24,
	PPM_SC_KILL = 25,
	PPM_SC_RENAME = 26,
	PPM_SC_MKDIR = 27,
	PPM_SC_RMDIR = 28,
	PPM_SC_DUP = 29,
	PPM_SC_PIPE = 30,
	PPM_SC_TIMES = 31,
	PPM_SC_BRK = 32,
	PPM_SC_ACCT = 33,
	PPM_SC_IOCTL = 34,
	PPM_SC_FCNTL = 35,
	PPM_SC_SETPGID = 36,
	PPM_SC_UMASK = 37,
	PPM_SC_CHROOT = 38,
	PPM_SC_USTAT = 39,
	PPM_SC_DUP2 = 40,
	PPM_SC_GETPPID = 41,
	PPM_SC_GETPGRP = 42,
	PPM_SC_SETSID = 43,
	PPM_SC_SETHOSTNAME = 44,
	PPM_SC_SETRLIMIT = 45,
	PPM_SC_GETRUSAGE = 46,
	PPM_SC_GETTIMEOFDAY = 47,
	PPM_SC_SETTIMEOFDAY = 48,
	PPM_SC_SYMLINK = 49,
	PPM_SC_LSTAT = 50,
	PPM_SC_READLINK = 51,
	PPM_SC_USELIB = 52,
	PPM_SC_SWAPON = 53,
	PPM_SC_REBOOT = 54,
	PPM_SC_MMAP = 55,
	PPM_SC_MUNMAP = 56,
	PPM_SC_TRUNCATE = 57,
	PPM_SC_FTRUNCATE = 58,
	PPM_SC_FCHMOD = 59,
	PPM_SC_GETPRIORITY = 60,
	PPM_SC_SETPRIORITY = 61,
	PPM_SC_STATFS = 62,
	PPM_SC_FSTATFS = 63,
	PPM_SC_SYSLOG = 64,
	PPM_SC_SETITIMER = 65,
	PPM_SC_GETITIMER = 66,
	PPM_SC_UNAME = 67,
	PPM_SC_VHANGUP = 68,
	PPM_SC_WAIT4 = 69,
	PPM_SC_SWAPOFF = 70,
	PPM_SC_SYSINFO = 71,
	PPM_SC_FSYNC = 72,
	PPM_SC_SETDOMAINNAME = 73,
	PPM_SC_ADJTIMEX = 74,
	PPM_SC_MPROTECT = 75,
	PPM_SC_INIT_MODULE = 76,
	PPM_SC_DELETE_MODULE = 77,
	PPM_SC_QUOTACTL = 78,
	PPM_SC_GETPGID = 79,
	PPM_SC_FCHDIR = 80,
	PPM_SC_SYSFS = 81,
	PPM_SC_PERSONALITY = 82,
	PPM_SC_GETDENTS = 83,
	PPM_SC_SELECT = 84,
	PPM_SC_FLOCK = 85,
	PPM_SC_MSYNC = 86,
	PPM_SC_READV = 87,
	PPM_SC_WRITEV = 88,
	PPM_SC_GETSID = 89,
	PPM_SC_FDATASYNC = 90,
	PPM_SC_MLOCK = 91,
	PPM_SC_MUNLOCK = 92,
	PPM_SC_MLOCKALL = 93,
	PPM_SC_MUNLOCKALL = 94,
	PPM_SC_SCHED_SETPARAM = 95,
	PPM_SC_SCHED_GETPARAM = 96,
	PPM_SC_SCHED_SETSCHEDULER = 97,
	PPM_SC_SCHED_GETSCHEDULER = 98,
	PPM_SC_SCHED_YIELD = 99,
	PPM_SC_SCHED_GET_PRIORITY_MAX = 100,
	PPM_SC_SCHED_GET_PRIORITY_MIN = 101,
	PPM_SC_SCHED_RR_GET_INTERVAL = 102,
	PPM_SC_NANOSLEEP = 103,
	PPM_SC_MREMAP = 104,
	PPM_SC_POLL = 105,
	PPM_SC_PRCTL = 106,
	PPM_SC_RT_SIGACTION = 107,
	PPM_SC_RT_SIGPROCMASK = 108,
	PPM_SC_RT_SIGPENDING = 109,
	PPM_SC_RT_SIGTIMEDWAIT = 110,
	PPM_SC_RT_SIGQUEUEINFO = 111,
	PPM_SC_RT_SIGSUSPEND = 112,
	PPM_SC_GETCWD = 113,
	PPM_SC_CAPGET = 114,
	PPM_SC_CAPSET = 115,
	PPM_SC_SENDFILE = 116,
	PPM_SC_GETRLIMIT = 117,
	PPM_SC_LCHOWN = 118,
	PPM_SC_GETUID = 119,
	PPM_SC_GETGID = 120,
	PPM_SC_GETEUID = 121,
	PPM_SC_GETEGID = 122,
	PPM_SC_SETREUID = 123,
	PPM_SC_SETREGID = 124,
	PPM_SC_GETGROUPS = 125,
	PPM_SC_SETGROUPS = 126,
	PPM_SC_FCHOWN = 127,
	PPM_SC_SETRESUID = 128,
	PPM_SC_GETRESUID = 129,
	PPM_SC_SETRESGID = 130,
	PPM_SC_GETRESGID = 131,
	PPM_SC_CHOWN = 132,
	PPM_SC_SETUID = 133,
	PPM_SC_SETGID = 134,
	PPM_SC_SETFSUID = 135,
	PPM_SC_SETFSGID = 136,
	PPM_SC_PIVOT_ROOT = 137,
	PPM_SC_MINCORE = 138,
	PPM_SC_MADVISE = 139,
	PPM_SC_GETTID = 140,
	PPM_SC_SETXATTR = 141,
	PPM_SC_LSETXATTR = 142,
	PPM_SC_FSETXATTR = 143,
	PPM_SC_GETXATTR = 144,
	PPM_SC_LGETXATTR = 145,
	PPM_SC_FGETXATTR = 146,
	PPM_SC_LISTXATTR = 147,
	PPM_SC_LLISTXATTR = 148,
	PPM_SC_FLISTXATTR = 149,
	PPM_SC_REMOVEXATTR = 150,
	PPM_SC_LREMOVEXATTR = 151,
	PPM_SC_FREMOVEXATTR = 152,
	PPM_SC_TKILL = 153,
	PPM_SC_FUTEX = 154,
	PPM_SC_SCHED_SETAFFINITY = 155,
	PPM_SC_SCHED_GETAFFINITY = 156,
	PPM_SC_SET_THREAD_AREA = 157,
	PPM_SC_GET_THREAD_AREA = 158,
	PPM_SC_IO_SETUP = 159,
	PPM_SC_IO_DESTROY = 160,
	PPM_SC_IO_GETEVENTS = 161,
	PPM_SC_IO_SUBMIT = 162,
	PPM_SC_IO_CANCEL = 163,
	PPM_SC_EXIT_GROUP = 164,
	PPM_SC_EPOLL_CREATE = 165,
	PPM_SC_EPOLL_CTL = 166,
	PPM_SC_EPOLL_WAIT = 167,
	PPM_SC_REMAP_FILE_PAGES = 168,
	PPM_SC_SET_TID_ADDRESS = 169,
	PPM_SC_TIMER_CREATE = 170,
	PPM_SC_TIMER_SETTIME = 171,
	PPM_SC_TIMER_GETTIME = 172,
	PPM_SC_TIMER_GETOVERRUN = 173,
	PPM_SC_TIMER_DELETE = 174,
	PPM_SC_CLOCK_SETTIME = 175,
	PPM_SC_CLOCK_GETTIME = 176,
	PPM_SC_CLOCK_GETRES = 177,
	PPM_SC_CLOCK_NANOSLEEP = 178,
	PPM_SC_TGKILL = 179,
	PPM_SC_UTIMES = 180,
	PPM_SC_MQ_OPEN = 181,
	PPM_SC_MQ_UNLINK = 182,
	PPM_SC_MQ_TIMEDSEND = 183,
	PPM_SC_MQ_TIMEDRECEIVE = 184,
	PPM_SC_MQ_NOTIFY = 185,
	PPM_SC_MQ_GETSETATTR = 186,
	PPM_SC_KEXEC_LOAD = 187,
	PPM_SC_WAITID = 188,
	PPM_SC_ADD_KEY = 189,
	PPM_SC_REQUEST_KEY = 190,
	PPM_SC_KEYCTL = 191,
	PPM_SC_IOPRIO_SET = 192,
	PPM_SC_IOPRIO_GET = 193,
	PPM_SC_INOTIFY_INIT = 194,
	PPM_SC_INOTIFY_ADD_WATCH = 195,
	PPM_SC_INOTIFY_RM_WATCH = 196,
	PPM_SC_OPENAT = 197,
	PPM_SC_MKDIRAT = 198,
	PPM_SC_MKNODAT = 199,
	PPM_SC_FCHOWNAT = 200,
	PPM_SC_FUTIMESAT = 201,
	PPM_SC_UNLINKAT = 202,
	PPM_SC_RENAMEAT = 203,
	PPM_SC_LINKAT = 204,
	PPM_SC_SYMLINKAT = 205,
	PPM_SC_READLINKAT = 206,
	PPM_SC_FCHMODAT = 207,
	PPM_SC_FACCESSAT = 208,
	PPM_SC_PSELECT6 = 209,
	PPM_SC_PPOLL = 210,
	PPM_SC_UNSHARE = 211,
	PPM_SC_SET_ROBUST_LIST = 212,
	PPM_SC_GET_ROBUST_LIST = 213,
	PPM_SC_SPLICE = 214,
	PPM_SC_TEE = 215,
	PPM_SC_VMSPLICE = 216,
	PPM_SC_GETCPU = 217,
	PPM_SC_EPOLL_PWAIT = 218,
	PPM_SC_UTIMENSAT = 219,
	PPM_SC_SIGNALFD = 220,
	PPM_SC_TIMERFD_CREATE = 221,
	PPM_SC_EVENTFD = 222,
	PPM_SC_TIMERFD_SETTIME = 223,
	PPM_SC_TIMERFD_GETTIME = 224,
	PPM_SC_SIGNALFD4 = 225,
	PPM_SC_EVENTFD2 = 226,
	PPM_SC_EPOLL_CREATE1 = 227,
	PPM_SC_DUP3 = 228,
	PPM_SC_PIPE2 = 229,
	PPM_SC_INOTIFY_INIT1 = 230,
	PPM_SC_PREADV = 231,
	PPM_SC_PWRITEV = 232,
	PPM_SC_RT_TGSIGQUEUEINFO = 233,
	PPM_SC_PERF_EVENT_OPEN = 234,
	PPM_SC_FANOTIFY_INIT = 235,
	PPM_SC_PRLIMIT64 = 236,
	PPM_SC_CLOCK_ADJTIME = 237,
	PPM_SC_SYNCFS = 238,
	PPM_SC_SETNS = 239,
	PPM_SC_GETDENTS64 = 240,
	PPM_SC_SOCKET = 241,
	PPM_SC_BIND = 242,
	PPM_SC_CONNECT = 243,
	PPM_SC_LISTEN = 244,
	PPM_SC_ACCEPT = 245,
	PPM_SC_GETSOCKNAME = 246,
	PPM_SC_GETPEERNAME = 247,
	PPM_SC_SOCKETPAIR = 248,
	PPM_SC_SENDTO = 249,
	PPM_SC_RECVFROM = 250,
	PPM_SC_SHUTDOWN = 251,
	PPM_SC_SETSOCKOPT = 252,
	PPM_SC_GETSOCKOPT = 253,
	PPM_SC_SENDMSG = 254,
	PPM_SC_SENDMMSG = 255,
	PPM_SC_RECVMSG = 256,
	PPM_SC_RECVMMSG = 257,
	PPM_SC_ACCEPT4 = 258,
	PPM_SC_SEMOP = 259,
	PPM_SC_SEMGET = 260,
	PPM_SC_SEMCTL = 261,
	PPM_SC_MSGSND = 262,
	PPM_SC_MSGRCV = 263,
	PPM_SC_MSGGET = 264,
	PPM_SC_MSGCTL = 265,
	PPM_SC_SHMDT = 266,
	PPM_SC_SHMGET = 267,
	PPM_SC_SHMCTL = 268,
	PPM_SC_STATFS64 = 269,
	PPM_SC_FSTATFS64 = 270,
	PPM_SC_FSTATAT64 = 271,
	PPM_SC_SENDFILE64 = 272,
	PPM_SC_UGETRLIMIT = 273,
	PPM_SC_BDFLUSH = 274,
	PPM_SC_SIGPROCMASK = 275,
	PPM_SC_IPC = 276,
	PPM_SC_SOCKETCALL = 277,
	PPM_SC_STAT64 = 278,
	PPM_SC_LSTAT64 = 279,
	PPM_SC_FSTAT64 = 280,
	PPM_SC_FCNTL64 = 281,
	PPM_SC_MMAP2 = 282,
	PPM_SC__NEWSELECT = 283,
	PPM_SC_SGETMASK = 284,
	PPM_SC_SSETMASK = 285,
	PPM_SC_SIGPENDING = 286,
	PPM_SC_OLDUNAME = 287,
	PPM_SC_UMOUNT = 288,
	PPM_SC_SIGNAL = 289,
	PPM_SC_NICE = 290,
	PPM_SC_STIME = 291,
	PPM_SC__LLSEEK = 292,
	PPM_SC_WAITPID = 293,
	PPM_SC_PREAD64 = 294,
	PPM_SC_PWRITE64 = 295,
	PPM_SC_ARCH_PRCTL = 296,
	PPM_SC_SHMAT = 297,
	PPM_SC_SIGRETURN = 298,
	PPM_SC_FALLOCATE = 299,
	PPM_SC_NEWFSSTAT = 300,
	PPM_SC_PROCESS_VM_READV = 301,
	PPM_SC_PROCESS_VM_WRITEV = 302,
	PPM_SC_FORK = 303,
	PPM_SC_VFORK = 304,
	PPM_SC_SETUID32 = 305,
	PPM_SC_GETUID32 = 306,
	PPM_SC_SETGID32 = 307,
	PPM_SC_GETEUID32 = 308,
	PPM_SC_GETGID32 = 309,
	PPM_SC_SETRESUID32 = 310,
	PPM_SC_SETRESGID32 = 311,
	PPM_SC_GETRESUID32 = 312,
	PPM_SC_GETRESGID32 = 313,
	PPM_SC_FINIT_MODULE = 314,
	PPM_SC_BPF = 315,
	PPM_SC_SECCOMP = 316,
	PPM_SC_SIGALTSTACK = 317,
	PPM_SC_GETRANDOM = 318,
	PPM_SC_FADVISE64 = 319,
	PPM_SC_MAX = 320,
};

/*
 * Event information enums
 */
enum ppm_event_category {
	EC_UNKNOWN = 0,	/* Unknown */
	EC_OTHER = 1,	/* No specific category */
	EC_FILE = 2,	/* File operation (open, close...) or file I/O */
	EC_NET = 3,		/* Network operation (socket, bind...) or network I/O */
	EC_IPC = 4,		/* IPC operation (pipe, futex...) or IPC I/O (e.g. on a pipe) */
	EC_MEMORY = 5,	/* Memory-related operation (e.g. brk) */
	EC_PROCESS = 6,	/* Process-related operation (fork, clone...) */
	EC_SLEEP = 7,	/* Plain sleep */
	EC_SYSTEM = 8,	/* System-related operations (e.g. reboot) */
	EC_SIGNAL = 9,	/* Signal-related operations (e.g. signal) */
	EC_USER = 10,	/* User-related operations (e.g. getuid) */
	EC_TIME = 11,	/* Time-related syscalls (e.g. gettimeofday) */
	EC_PROCESSING = 12,	/* User level processing. Never used for system calls */
	EC_IO_BASE = 32,/* used for masking */
	EC_IO_READ = 32,/* General I/O read (can be file, socket, IPC...) */
	EC_IO_WRITE = 33,/* General I/O write (can be file, socket, IPC...) */
	EC_IO_OTHER = 34,/* General I/O that is neither read not write (can be file, socket, IPC...) */
	EC_WAIT = 64,	/* General wait (can be file, socket, IPC...) */
	EC_SCHEDULER = 128,	/* Scheduler event (e.g. context switch) */
	EC_INTERNAL = 256,	/* Internal event that shouldn't be shown to the user */
};

enum ppm_event_flags {
	EF_NONE = 0,
	EF_CREATES_FD = (1 << 0), /* This event creates an FD (e.g. open) */
	EF_DESTROYS_FD = (1 << 1), /* This event destroys an FD (e.g. close) */
	EF_USES_FD = (1 << 2), /* This event operates on an FD. */
	EF_READS_FROM_FD = (1 << 3), /* This event reads data from an FD. */
	EF_WRITES_TO_FD = (1 << 4), /* This event writes data to an FD. */
	EF_MODIFIES_STATE = (1 << 5), /* This event causes the machine state to change and should not be dropped by the filtering engine. */
	EF_UNUSED = (1 << 6), /* This event is not used */
	EF_WAITS = (1 << 7), /* This event reads data from an FD. */
	EF_SKIPPARSERESET = (1 << 8), /* This event shouldn't pollute the parser lastevent state tracker. */
	EF_OLD_VERSION = (1 << 9), /* This event is kept for backward compatibility */
	EF_DROP_SIMPLE_CONS = (1 << 10) /* This event can be skipped by consumers that privilege low overhead to full event capture */
};

/*
 * types of event parameters
 */
enum ppm_param_type {
	PT_NONE = 0,
	PT_INT8 = 1,
	PT_INT16 = 2,
	PT_INT32 = 3,
	PT_INT64 = 4,
	PT_UINT8 = 5,
	PT_UINT16 = 6,
	PT_UINT32 = 7,
	PT_UINT64 = 8,
	PT_CHARBUF = 9,	/* A printable buffer of bytes, NULL terminated */
	PT_BYTEBUF = 10, /* A raw buffer of bytes not suitable for printing */
	PT_ERRNO = 11,	/* this is an INT64, but will be interpreted as an error code */
	PT_SOCKADDR = 12, /* A sockaddr structure, 1byte family + data */
	PT_SOCKTUPLE = 13, /* A sockaddr tuple,1byte family + 12byte data + 12byte data */
	PT_FD = 14, /* An fd, 64bit */
	PT_PID = 15, /* A pid/tid, 64bit */
	PT_FDLIST = 16, /* A list of fds, 16bit count + count * (64bit fd + 16bit flags) */
	PT_FSPATH = 17,	/* A string containing a relative or absolute file system path, null terminated */
	PT_SYSCALLID = 18, /* A 16bit system call ID. Can be used as a key for the g_syscall_info_table table. */
	PT_SIGTYPE = 19, /* An 8bit signal number */
	PT_RELTIME = 20, /* A relative time. Seconds * 10^9  + nanoseconds. 64bit. */
	PT_ABSTIME = 21, /* An absolute time interval. Seconds from epoch * 10^9  + nanoseconds. 64bit. */
	PT_PORT = 22, /* A TCP/UDP prt. 2 bytes. */
	PT_L4PROTO = 23, /* A 1 byte IP protocol type. */
	PT_SOCKFAMILY = 24, /* A 1 byte socket family. */
	PT_BOOL = 25, /* A boolean value, 4 bytes. */
	PT_IPV4ADDR = 26, /* A 4 byte raw IPv4 address. */
	PT_DYN = 27, /* Type can vary depending on the context. Used for filter fields like evt.rawarg. */
	PT_FLAGS8 = 28, /* this is an UINT8, but will be interpreted as 8 bit flags. */
	PT_FLAGS16 = 29, /* this is an UINT16, but will be interpreted as 16 bit flags. */
	PT_FLAGS32 = 30, /* this is an UINT32, but will be interpreted as 32 bit flags. */
	PT_UID = 31, /* this is an UINT32, MAX_UINT32 will be interpreted as no value. */
	PT_GID = 32, /* this is an UINT32, MAX_UINT32 will be interpreted as no value. */
	PT_DOUBLE = 33, /* this is a double precision floating point number. */
	PT_SIGSET = 34, /* sigset_t. I only store the lower UINT32 of it */
	PT_CHARBUFARRAY = 35,	/* Pointer to an array of strings, exported by the user events decoder. 64bit. For internal use only. */
	PT_CHARBUF_PAIR_ARRAY = 36,	/* Pointer to an array of string pairs, exported by the user events decoder. 64bit. For internal use only. */
	PT_IPV4NET = 37, /* An IPv4 network. */
	PT_IPV6ADDR = 38, /* A 16 byte raw IPv6 address. */
	PT_IPV6NET = 39, /* An IPv6 network. */
	PT_IPADDR = 40,  /* Either an IPv4 or IPv6 address. The length indicates which one it is. */
	PT_IPNET = 41,  /* Either an IPv4 or IPv6 network. The length indicates which one it is. */
	PT_MODE = 42, /* a 32 bit bitmask to represent file modes. */
	PT_MAX = 43 /* array size */
};

enum ppm_print_format {
	PF_NA = 0,
	PF_DEC = 1,	/* decimal */
	PF_HEX = 2,	/* hexadecimal */
	PF_10_PADDED_DEC = 3, /* decimal padded to 10 digits, useful to print the fractional part of a ns timestamp */
	PF_ID = 4,
	PF_DIR = 5,
	PF_OCT = 6,	/* octal */
};

/*!
  \brief Name-value pair, used to store flags information.
*/
struct ppm_name_value {
	const char *name;
	uint32_t value;
};

/*!
  \brief Event parameter information.
*/
struct ppm_param_info {
	char name[PPM_MAX_NAME_LEN];  /**< Parameter name, e.g. 'size'. */
	enum ppm_param_type type; /**< Parameter type, e.g. 'uint16', 'string'... */
	enum ppm_print_format fmt; /**< If this is a numeric parameter, this flag specifies if it should be rendered as decimal or hex. */
	const void *info; /**< If this is a flags parameter, it points to an array of ppm_name_value,
			       else if this is a dynamic parameter it points to an array of ppm_param_info */
	uint8_t ninfo; /**< Number of entry in the info array. */
} _packed;

/*!
  \brief Event information.
  This structure contains the full description of an event type (e.g. 'open') that
   is supported by the sysdig infrastructure.
*/
struct ppm_event_info {
	char name[PPM_MAX_NAME_LEN]; /**< Name. */
	enum ppm_event_category category; /**< Event category, e.g. 'file', 'net', etc. */
	enum ppm_event_flags flags; /**< flags for this event. */
	uint32_t nparams; /**< Number of parameter in the params array. */
	struct ppm_param_info params[PPM_MAX_EVENT_PARAMS]; /**< parameters descriptions. */
} _packed;

#if defined _MSC_VER
#pragma pack(push)
#pragma pack(1)
#elif defined __sun
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif
struct ppm_evt_hdr {
#ifdef PPM_ENABLE_SENTINEL
	uint32_t sentinel_begin;
#endif
	uint64_t ts; /* timestamp, in nanoseconds from epoch */
	uint64_t tid; /* the tid of the thread that generated this event */
	uint32_t len; /* the event len, including the header */
	uint16_t type; /* the event type */
	uint32_t nparams; /* the number of parameters of the event */
};
#if defined __sun
#pragma pack()
#else
#pragma pack(pop)
#endif

/*
 * IOCTL codes
 */
#ifndef CYGWING_AGENT
#define PPM_IOCTL_MAGIC	's'
#define PPM_IOCTL_DISABLE_CAPTURE _IO(PPM_IOCTL_MAGIC, 0)
#define PPM_IOCTL_ENABLE_CAPTURE _IO(PPM_IOCTL_MAGIC, 1)
#define PPM_IOCTL_DISABLE_DROPPING_MODE _IO(PPM_IOCTL_MAGIC, 2)
#define PPM_IOCTL_ENABLE_DROPPING_MODE _IO(PPM_IOCTL_MAGIC, 3)
#define PPM_IOCTL_SET_SNAPLEN _IO(PPM_IOCTL_MAGIC, 4)
#define PPM_IOCTL_MASK_ZERO_EVENTS _IO(PPM_IOCTL_MAGIC, 5)
#define PPM_IOCTL_MASK_SET_EVENT   _IO(PPM_IOCTL_MAGIC, 6)
#define PPM_IOCTL_MASK_UNSET_EVENT _IO(PPM_IOCTL_MAGIC, 7)
#define PPM_IOCTL_DISABLE_DYNAMIC_SNAPLEN _IO(PPM_IOCTL_MAGIC, 8)
#define PPM_IOCTL_ENABLE_DYNAMIC_SNAPLEN _IO(PPM_IOCTL_MAGIC, 9)
#define PPM_IOCTL_GET_VTID _IO(PPM_IOCTL_MAGIC, 10)
#define PPM_IOCTL_GET_VPID _IO(PPM_IOCTL_MAGIC, 11)
#define PPM_IOCTL_GET_CURRENT_TID _IO(PPM_IOCTL_MAGIC, 12)
#define PPM_IOCTL_GET_CURRENT_PID _IO(PPM_IOCTL_MAGIC, 13)
#define PPM_IOCTL_DISABLE_SIGNAL_DELIVER _IO(PPM_IOCTL_MAGIC, 14)
#define PPM_IOCTL_ENABLE_SIGNAL_DELIVER _IO(PPM_IOCTL_MAGIC, 15)
#define PPM_IOCTL_GET_PROCLIST _IO(PPM_IOCTL_MAGIC, 16)
#define PPM_IOCTL_SET_TRACERS_CAPTURE _IO(PPM_IOCTL_MAGIC, 17)
#define PPM_IOCTL_SET_SIMPLE_MODE _IO(PPM_IOCTL_MAGIC, 18)
#define PPM_IOCTL_ENABLE_PAGE_FAULTS _IO(PPM_IOCTL_MAGIC, 19)
#define PPM_IOCTL_GET_N_TRACEPOINT_HIT _IO(PPM_IOCTL_MAGIC, 20)
#define PPM_IOCTL_GET_PROBE_VERSION _IO(PPM_IOCTL_MAGIC, 21)
#define PPM_IOCTL_SET_FULLCAPTURE_PORT_RANGE _IO(PPM_IOCTL_MAGIC, 22)
#define PPM_IOCTL_SET_STATSD_PORT _IO(PPM_IOCTL_MAGIC, 23)
#endif // CYGWING_AGENT

extern const struct ppm_name_value socket_families[];
extern const struct ppm_name_value file_flags[];
extern const struct ppm_name_value flock_flags[];
extern const struct ppm_name_value clone_flags[];
extern const struct ppm_name_value futex_operations[];
extern const struct ppm_name_value lseek_whence[];
extern const struct ppm_name_value poll_flags[];
extern const struct ppm_name_value mount_flags[];
extern const struct ppm_name_value umount_flags[];
extern const struct ppm_name_value shutdown_how[];
extern const struct ppm_name_value rlimit_resources[];
extern const struct ppm_name_value fcntl_commands[];
extern const struct ppm_name_value sockopt_levels[];
extern const struct ppm_name_value sockopt_options[];
extern const struct ppm_name_value ptrace_requests[];
extern const struct ppm_name_value prot_flags[];
extern const struct ppm_name_value mmap_flags[];
extern const struct ppm_name_value splice_flags[];
extern const struct ppm_name_value quotactl_cmds[];
extern const struct ppm_name_value quotactl_types[];
extern const struct ppm_name_value quotactl_dqi_flags[];
extern const struct ppm_name_value quotactl_quota_fmts[];
extern const struct ppm_name_value semop_flags[];
extern const struct ppm_name_value semget_flags[];
extern const struct ppm_name_value semctl_commands[];
extern const struct ppm_name_value access_flags[];
extern const struct ppm_name_value pf_flags[];
extern const struct ppm_name_value unlinkat_flags[];
extern const struct ppm_name_value linkat_flags[];
extern const struct ppm_name_value chmod_mode[];

extern const struct ppm_param_info sockopt_dynamic_param[];
extern const struct ppm_param_info ptrace_dynamic_param[];
extern const struct ppm_param_info bpf_dynamic_param[];

/*
 * Driver event notification ID
 */
enum ppm_driver_event_id {
	DEI_NONE = 0,
	DEI_DISABLE_DROPPING = 1,
	DEI_ENABLE_DROPPING = 2,
};

/*!
  \brief Process information as returned by the PPM_IOCTL_GET_PROCLIST IOCTL.
*/
struct ppm_proc_info {
	uint64_t pid;
	uint64_t utime;
	uint64_t stime;
};

struct ppm_proclist_info {
	int64_t n_entries;
	int64_t max_entries;
	struct ppm_proc_info entries[0];
};

enum syscall_flags {
	UF_NONE = 0,
	UF_USED = (1 << 0),
	UF_NEVER_DROP = (1 << 1),
	UF_ALWAYS_DROP = (1 << 2),
	UF_SIMPLEDRIVER_KEEP = (1 << 3),
	UF_ATOMIC = (1 << 4), ///< The handler should not block (interrupt context)
};

struct syscall_evt_pair {
	int flags;
	enum ppm_event_type enter_event_type;
	enum ppm_event_type exit_event_type;
} _packed;

#define SYSCALL_TABLE_SIZE 512

/*
 * Filler table-related definitions
 */

#define PPM_MAX_AUTOFILL_ARGS (1 << 2)

/*
 * Max size of a parameter in the kernel module is u16, so no point
 * in going beyond 0xffff. However, in BPF the limit is more stringent
 * because the entire perf event must fit in u16, so make this
 * a more conservative 65k so we have some room for the other
 * parameters in the event. It shouldn't cause issues since typically
 * snaplen is much lower than this.
 */
#define PPM_MAX_ARG_SIZE 65000

struct event_filler_arguments;

#include "ppm_fillers.h"

struct ppm_autofill_arg {
#define AF_ID_RETVAL -1
#define AF_ID_USEDEFAULT -2
	int16_t id;
	long default_val;
} _packed;

enum autofill_paramtype {
	APT_REG,
	APT_SOCK,
};

typedef int (*filler_callback) (struct event_filler_arguments *args);

struct ppm_event_entry {
	filler_callback filler_callback;
	enum ppm_filler_id filler_id;
	uint16_t n_autofill_args;
	enum autofill_paramtype paramtype;
	struct ppm_autofill_arg autofill_args[PPM_MAX_AUTOFILL_ARGS];
} _packed;

/*
 * parse_readv_writev_bufs flags
 */
#define PRB_FLAG_PUSH_SIZE	1
#define PRB_FLAG_PUSH_DATA	2
#define PRB_FLAG_PUSH_ALL	(PRB_FLAG_PUSH_SIZE | PRB_FLAG_PUSH_DATA)
#define PRB_FLAG_IS_WRITE	4

/*
 * Return codes
 */
#define PPM_SUCCESS 0
#define PPM_FAILURE_BUFFER_FULL -1
#define PPM_FAILURE_INVALID_USER_MEMORY -2
#define PPM_FAILURE_BUG -3
#define PPM_SKIP_EVENT -4

#define RW_SNAPLEN 80
#define RW_MAX_SNAPLEN PPM_MAX_ARG_SIZE
#define RW_MAX_FULLCAPTURE_PORT_SNAPLEN 16000

#endif /* EVENTS_PUBLIC_H_ */
