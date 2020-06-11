/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifdef __KERNEL__
#include <linux/kobject.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kdev_t.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <net/sock.h>
#include <asm/unistd.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20)
#include "ppm_syscall.h"
#else
#include <asm/syscall.h>
#endif
#else /* __KERNEL__ */
#include <linux/unistd.h>
#define SYSCALL_TABLE_ID0 0
#endif /* __KERNEL__ */

#include "ppm_events_public.h"
#ifdef __KERNEL__
#include "ppm.h"
#if defined(CONFIG_IA32_EMULATION) && !defined(__NR_ia32_socketcall)
#include "ppm_compat_unistd_32.h"
#endif
#endif /* __KERNEL__ */

/*
 * SYSCALL TABLE
 */
const struct syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE] = {
	[__NR_open - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_OPEN_E, PPME_SYSCALL_OPEN_X},
	[__NR_creat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CREAT_E, PPME_SYSCALL_CREAT_X},
	[__NR_close - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X},
	[__NR_brk - SYSCALL_TABLE_ID0] =                        {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_BRK_4_E, PPME_SYSCALL_BRK_4_X},
	[__NR_read - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_READ_E, PPME_SYSCALL_READ_X},
	[__NR_write - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_WRITE_E, PPME_SYSCALL_WRITE_X},
	[__NR_execve - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_EXECVE_19_E, PPME_SYSCALL_EXECVE_19_X},
	[__NR_clone - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_CLONE_20_E, PPME_SYSCALL_CLONE_20_X},
	[__NR_fork - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_FORK_20_E, PPME_SYSCALL_FORK_20_X},
	[__NR_vfork - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_VFORK_20_E, PPME_SYSCALL_VFORK_20_X},
	[__NR_pipe - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PIPE_E, PPME_SYSCALL_PIPE_X},
	[__NR_pipe2 - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PIPE_E, PPME_SYSCALL_PIPE_X},
	[__NR_eventfd - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X},
	[__NR_eventfd2 - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X},
	[__NR_futex - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FUTEX_E, PPME_SYSCALL_FUTEX_X},
	[__NR_stat - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_STAT_E, PPME_SYSCALL_STAT_X},
	[__NR_lstat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_LSTAT_E, PPME_SYSCALL_LSTAT_X},
	[__NR_fstat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FSTAT_E, PPME_SYSCALL_FSTAT_X},
	[__NR_epoll_wait - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_EPOLLWAIT_E, PPME_SYSCALL_EPOLLWAIT_X},
	[__NR_poll - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_POLL_E, PPME_SYSCALL_POLL_X},
#ifdef __NR_select
	[__NR_select - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SELECT_E, PPME_SYSCALL_SELECT_X},
#endif
	[__NR_lseek - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_LSEEK_E, PPME_SYSCALL_LSEEK_X},
	[__NR_ioctl - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_IOCTL_3_E, PPME_SYSCALL_IOCTL_3_X},
	[__NR_getcwd - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_GETCWD_E, PPME_SYSCALL_GETCWD_X},
	[__NR_chdir - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_CHDIR_E, PPME_SYSCALL_CHDIR_X},
	[__NR_fchdir - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_FCHDIR_E, PPME_SYSCALL_FCHDIR_X},
	[__NR_mkdir - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_MKDIR_2_E, PPME_SYSCALL_MKDIR_2_X},
	[__NR_rmdir - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_RMDIR_2_E, PPME_SYSCALL_RMDIR_2_X},
	[__NR_openat - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X},
	[__NR_mkdirat - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_MKDIRAT_E, PPME_SYSCALL_MKDIRAT_X},
	[__NR_link - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_LINK_2_E, PPME_SYSCALL_LINK_2_X},
	[__NR_linkat - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_LINKAT_2_E, PPME_SYSCALL_LINKAT_2_X},
	[__NR_unlink - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_UNLINK_2_E, PPME_SYSCALL_UNLINK_2_X},
	[__NR_unlinkat - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_UNLINKAT_2_E, PPME_SYSCALL_UNLINKAT_2_X},
	[__NR_pread64 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_PREAD_E, PPME_SYSCALL_PREAD_X},
	[__NR_pwrite64 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_PWRITE_E, PPME_SYSCALL_PWRITE_X},
	[__NR_readv - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_READV_E, PPME_SYSCALL_READV_X},
	[__NR_writev - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_WRITEV_E, PPME_SYSCALL_WRITEV_X},
	[__NR_preadv - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_PREADV_E, PPME_SYSCALL_PREADV_X},
	[__NR_pwritev - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_PWRITEV_E, PPME_SYSCALL_PWRITEV_X},
	[__NR_dup - SYSCALL_TABLE_ID0] =                        {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_dup2 - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_dup3 - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_signalfd - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SIGNALFD_E, PPME_SYSCALL_SIGNALFD_X},
	[__NR_signalfd4 - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SIGNALFD_E, PPME_SYSCALL_SIGNALFD_X},
	[__NR_kill - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_KILL_E, PPME_SYSCALL_KILL_X},
	[__NR_tkill - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_TKILL_E, PPME_SYSCALL_TKILL_X},
	[__NR_tgkill - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_TGKILL_E, PPME_SYSCALL_TGKILL_X},
	[__NR_nanosleep - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_NANOSLEEP_E, PPME_SYSCALL_NANOSLEEP_X},
	[__NR_timerfd_create - SYSCALL_TABLE_ID0] =             {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_TIMERFD_CREATE_E, PPME_SYSCALL_TIMERFD_CREATE_X},
	[__NR_inotify_init - SYSCALL_TABLE_ID0] =               {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_INOTIFY_INIT_E, PPME_SYSCALL_INOTIFY_INIT_X},
	[__NR_inotify_init1 - SYSCALL_TABLE_ID0] =              {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_INOTIFY_INIT_E, PPME_SYSCALL_INOTIFY_INIT_X},
	[__NR_fchmodat - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_FCHMODAT_E, PPME_SYSCALL_FCHMODAT_X},
	[__NR_fchmod - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_FCHMOD_E, PPME_SYSCALL_FCHMOD_X},
#ifdef __NR_getrlimit
	[__NR_getrlimit - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_GETRLIMIT_E, PPME_SYSCALL_GETRLIMIT_X},
#endif
	[__NR_setrlimit - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SETRLIMIT_E, PPME_SYSCALL_SETRLIMIT_X},
#ifdef __NR_prlimit64
	[__NR_prlimit64 - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PRLIMIT_E, PPME_SYSCALL_PRLIMIT_X},
#endif
#ifdef __NR_ugetrlimit
	[__NR_ugetrlimit - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_GETRLIMIT_E, PPME_SYSCALL_GETRLIMIT_X},
#endif
	[__NR_fcntl - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_FCNTL_E, PPME_SYSCALL_FCNTL_X},
#ifdef __NR_fcntl64
	[__NR_fcntl64 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_FCNTL_E, PPME_SYSCALL_FCNTL_X},
#endif
/* [__NR_old_select - SYSCALL_TABLE_ID0] =	{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X}, */
	[__NR_pselect6 - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_epoll_create - SYSCALL_TABLE_ID0] =               {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_epoll_ctl - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_uselib - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_sched_setparam - SYSCALL_TABLE_ID0] =             {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_sched_getparam - SYSCALL_TABLE_ID0] =             {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_syslog - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_chmod - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_CHMOD_E, PPME_SYSCALL_CHMOD_X},
	[__NR_lchown - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
#ifdef __NR_utime
	[__NR_utime - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
	[__NR_mount - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_MOUNT_E, PPME_SYSCALL_MOUNT_X},
	[__NR_umount2 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_UMOUNT_E, PPME_SYSCALL_UMOUNT_X},
	[__NR_ptrace - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_PTRACE_E, PPME_SYSCALL_PTRACE_X},
#ifdef __NR_alarm
	[__NR_alarm - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
	[__NR_pause - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},

#ifndef __NR_socketcall
	[__NR_socket - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SOCKET_SOCKET_E, PPME_SOCKET_SOCKET_X},
	[__NR_bind - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SOCKET_BIND_E,  PPME_SOCKET_BIND_X},
	[__NR_connect - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_SIMPLEDRIVER_KEEP, PPME_SOCKET_CONNECT_E, PPME_SOCKET_CONNECT_X},
	[__NR_listen - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SOCKET_LISTEN_E, PPME_SOCKET_LISTEN_X},
	[__NR_accept - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_SIMPLEDRIVER_KEEP, PPME_SOCKET_ACCEPT_5_E, PPME_SOCKET_ACCEPT_5_X},
	[__NR_getsockname - SYSCALL_TABLE_ID0] =                {UF_USED | UF_ALWAYS_DROP, PPME_SOCKET_GETSOCKNAME_E, PPME_SOCKET_GETSOCKNAME_X},
	[__NR_getpeername - SYSCALL_TABLE_ID0] =                {UF_USED | UF_ALWAYS_DROP, PPME_SOCKET_GETPEERNAME_E, PPME_SOCKET_GETPEERNAME_X},
	[__NR_socketpair - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_NEVER_DROP, PPME_SOCKET_SOCKETPAIR_E, PPME_SOCKET_SOCKETPAIR_X},
	[__NR_sendto - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SOCKET_SENDTO_E, PPME_SOCKET_SENDTO_X},
	[__NR_recvfrom - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_RECVFROM_E, PPME_SOCKET_RECVFROM_X},
	[__NR_shutdown - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_SHUTDOWN_E, PPME_SOCKET_SHUTDOWN_X},
	[__NR_setsockopt - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_ALWAYS_DROP, PPME_SOCKET_SETSOCKOPT_E, PPME_SOCKET_SETSOCKOPT_X},
	[__NR_getsockopt - SYSCALL_TABLE_ID0] =                 {UF_USED, PPME_SOCKET_GETSOCKOPT_E, PPME_SOCKET_GETSOCKOPT_X},
	[__NR_sendmsg - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SOCKET_SENDMSG_E, PPME_SOCKET_SENDMSG_X},
	[__NR_accept4 - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_SIMPLEDRIVER_KEEP, PPME_SOCKET_ACCEPT4_5_E, PPME_SOCKET_ACCEPT4_5_X},
#endif

#ifdef __NR_sendmmsg
	[__NR_sendmmsg - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_SENDMMSG_E, PPME_SOCKET_SENDMMSG_X},
#endif
#ifdef __NR_recvmsg
	[__NR_recvmsg - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SOCKET_RECVMSG_E, PPME_SOCKET_RECVMSG_X},
#endif
#ifdef __NR_recvmmsg
	[__NR_recvmmsg - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_RECVMMSG_E, PPME_SOCKET_RECVMMSG_X},
#endif
#ifdef __NR_stat64
	[__NR_stat64 - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_STAT64_E, PPME_SYSCALL_STAT64_X},
#endif
#ifdef __NR_fstat64
	[__NR_fstat64 - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FSTAT64_E, PPME_SYSCALL_FSTAT64_X},
#endif
#ifdef __NR__llseek
	[__NR__llseek - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_LLSEEK_E, PPME_SYSCALL_LLSEEK_X},
#endif
#ifdef __NR_mmap
	[__NR_mmap - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_MMAP_E, PPME_SYSCALL_MMAP_X},
#endif
#ifdef __NR_mmap2
	[__NR_mmap2 - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_MMAP2_E, PPME_SYSCALL_MMAP2_X},
#endif
	[__NR_munmap - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_MUNMAP_E, PPME_SYSCALL_MUNMAP_X},
	[__NR_splice - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_SPLICE_E, PPME_SYSCALL_SPLICE_X},
#ifdef __NR_process_vm_readv
	[__NR_process_vm_readv - SYSCALL_TABLE_ID0] =           {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_process_vm_writev
	[__NR_process_vm_writev - SYSCALL_TABLE_ID0] =          {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
#endif

	[__NR_rename - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_RENAME_E, PPME_SYSCALL_RENAME_X},
	[__NR_renameat - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_RENAMEAT_E, PPME_SYSCALL_RENAMEAT_X},
	[__NR_symlink - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_SYMLINK_E, PPME_SYSCALL_SYMLINK_X},
	[__NR_symlinkat - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_SYMLINKAT_E, PPME_SYSCALL_SYMLINKAT_X},
	[__NR_sendfile - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_SENDFILE_E, PPME_SYSCALL_SENDFILE_X},
#ifdef __NR_sendfile64
	[__NR_sendfile64 - SYSCALL_TABLE_ID0] =                 {UF_USED, PPME_SYSCALL_SENDFILE_E, PPME_SYSCALL_SENDFILE_X},
#endif
#ifdef __NR_quotactl
	[__NR_quotactl - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_QUOTACTL_E, PPME_SYSCALL_QUOTACTL_X},
#endif
#ifdef __NR_setresuid
	[__NR_setresuid - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_SETRESUID_E, PPME_SYSCALL_SETRESUID_X },
#endif
#ifdef __NR_setresuid32
	[__NR_setresuid32 - SYSCALL_TABLE_ID0] =                {UF_USED, PPME_SYSCALL_SETRESUID_E, PPME_SYSCALL_SETRESUID_X },
#endif
#ifdef __NR_setresgid
	[__NR_setresgid - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_SETRESGID_E, PPME_SYSCALL_SETRESGID_X },
#endif
#ifdef __NR_setresgid32
	[__NR_setresgid32 - SYSCALL_TABLE_ID0] =                {UF_USED, PPME_SYSCALL_SETRESGID_E, PPME_SYSCALL_SETRESGID_X },
#endif
#ifdef __NR_setuid
	[__NR_setuid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_SETUID_E, PPME_SYSCALL_SETUID_X },
#endif
#ifdef __NR_setuid32
	[__NR_setuid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_SETUID_E, PPME_SYSCALL_SETUID_X },
#endif
#ifdef __NR_setgid
	[__NR_setgid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_SETGID_E, PPME_SYSCALL_SETGID_X },
#endif
#ifdef __NR_setgid32
	[__NR_setgid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_SETGID_E, PPME_SYSCALL_SETGID_X },
#endif
#ifdef __NR_getuid
	[__NR_getuid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_GETUID_E, PPME_SYSCALL_GETUID_X },
#endif
#ifdef __NR_getuid32
	[__NR_getuid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_GETUID_E, PPME_SYSCALL_GETUID_X },
#endif
#ifdef __NR_geteuid
	[__NR_geteuid - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_GETEUID_E, PPME_SYSCALL_GETEUID_X },
#endif
#ifdef __NR_geteuid32
	[__NR_geteuid32 - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_GETEUID_E, PPME_SYSCALL_GETEUID_X },
#endif
#ifdef __NR_getgid
	[__NR_getgid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_GETGID_E, PPME_SYSCALL_GETGID_X },
#endif
#ifdef __NR_getgid32
	[__NR_getgid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_GETGID_E, PPME_SYSCALL_GETGID_X },
#endif
#ifdef __NR_getegid
	[__NR_getegid - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_GETEGID_E, PPME_SYSCALL_GETEGID_X },
#endif
#ifdef __NR_getegid32
	[__NR_getegid32 - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_GETEGID_E, PPME_SYSCALL_GETEGID_X },
#endif
#ifdef __NR_getresuid
	[__NR_getresuid - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_GETRESUID_E, PPME_SYSCALL_GETRESUID_X },
#endif
#ifdef __NR_getresuid32
	[__NR_getresuid32 - SYSCALL_TABLE_ID0] =                {UF_USED, PPME_SYSCALL_GETRESUID_E, PPME_SYSCALL_GETRESUID_X },
#endif
#ifdef __NR_getresgid
	[__NR_getresgid - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_GETRESGID_E, PPME_SYSCALL_GETRESGID_X },
#endif
#ifdef __NR_getresgid32
	[__NR_getresgid32 - SYSCALL_TABLE_ID0] =                {UF_USED, PPME_SYSCALL_GETRESGID_E, PPME_SYSCALL_GETRESGID_X },
#endif
	[__NR_getdents - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_GETDENTS_E, PPME_SYSCALL_GETDENTS_X},
	[__NR_getdents64 - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_GETDENTS64_E, PPME_SYSCALL_GETDENTS64_X},
#ifdef __NR_setns
	[__NR_setns - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_SETNS_E, PPME_SYSCALL_SETNS_X},
#endif
#ifdef __NR_unshare
	[__NR_unshare - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_UNSHARE_E, PPME_SYSCALL_UNSHARE_X},
#endif
	[__NR_flock - SYSCALL_TABLE_ID0] =			{UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FLOCK_E, PPME_SYSCALL_FLOCK_X},
#ifdef __NR_semop
	[__NR_semop - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SEMOP_E, PPME_SYSCALL_SEMOP_X},
#endif
#ifdef __NR_semget
	[__NR_semget - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SEMGET_E, PPME_SYSCALL_SEMGET_X},
#endif
#ifdef __NR_semctl
	[__NR_semctl - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SEMCTL_E, PPME_SYSCALL_SEMCTL_X},
#endif
	[__NR_ppoll - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_PPOLL_E, PPME_SYSCALL_PPOLL_X},
#ifdef __NR_access
	[__NR_access - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_ACCESS_E, PPME_SYSCALL_ACCESS_X},
#endif
#ifdef __NR_chroot
	[__NR_chroot - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CHROOT_E, PPME_SYSCALL_CHROOT_X},
#endif
	[__NR_setsid - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SETSID_E, PPME_SYSCALL_SETSID_X},
	[__NR_setpgid - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SETPGID_E, PPME_SYSCALL_SETPGID_X},
#ifdef __NR_bpf
	[__NR_bpf - SYSCALL_TABLE_ID0] =                        {UF_USED, PPME_SYSCALL_BPF_E, PPME_SYSCALL_BPF_X},
#endif
#ifdef __NR_seccomp
	[__NR_seccomp - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_SECCOMP_E, PPME_SYSCALL_SECCOMP_X},
#endif
};

/*
 * SYSCALL ROUTING TABLE
 */
const enum ppm_syscall_code g_syscall_code_routing_table[SYSCALL_TABLE_SIZE] = {
	[__NR_restart_syscall - SYSCALL_TABLE_ID0] = PPM_SC_RESTART_SYSCALL,
	[__NR_exit - SYSCALL_TABLE_ID0] = PPM_SC_EXIT,
	[__NR_read - SYSCALL_TABLE_ID0] = PPM_SC_READ,
	[__NR_write - SYSCALL_TABLE_ID0] = PPM_SC_WRITE,
	[__NR_open - SYSCALL_TABLE_ID0] = PPM_SC_OPEN,
	[__NR_close - SYSCALL_TABLE_ID0] = PPM_SC_CLOSE,
	[__NR_creat - SYSCALL_TABLE_ID0] = PPM_SC_CREAT,
	[__NR_link - SYSCALL_TABLE_ID0] = PPM_SC_LINK,
	[__NR_unlink - SYSCALL_TABLE_ID0] = PPM_SC_UNLINK,
	[__NR_chdir - SYSCALL_TABLE_ID0] = PPM_SC_CHDIR,
#ifdef __NR_time
	[__NR_time - SYSCALL_TABLE_ID0] = PPM_SC_TIME,
#endif
	[__NR_mknod - SYSCALL_TABLE_ID0] = PPM_SC_MKNOD,
	[__NR_chmod - SYSCALL_TABLE_ID0] = PPM_SC_CHMOD,
/* [__NR_lchown16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_LCHOWN16, */
	[__NR_stat - SYSCALL_TABLE_ID0] = PPM_SC_STAT,
	[__NR_lseek - SYSCALL_TABLE_ID0] = PPM_SC_LSEEK,
	[__NR_getpid - SYSCALL_TABLE_ID0] = PPM_SC_GETPID,
	[__NR_mount - SYSCALL_TABLE_ID0] = PPM_SC_MOUNT,
/* [__NR_oldumount - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLDUMOUNT, */
/* [__NR_setuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETUID16, */
/* [__NR_getuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETUID16, */
	[__NR_ptrace - SYSCALL_TABLE_ID0] = PPM_SC_PTRACE,
#ifdef __NR_alarm
	[__NR_alarm - SYSCALL_TABLE_ID0] = PPM_SC_ALARM,
#endif
	[__NR_fstat - SYSCALL_TABLE_ID0] = PPM_SC_FSTAT,
	[__NR_pause - SYSCALL_TABLE_ID0] = PPM_SC_PAUSE,
#ifdef __NR_utime
	[__NR_utime - SYSCALL_TABLE_ID0] = PPM_SC_UTIME,
#endif
	[__NR_sync - SYSCALL_TABLE_ID0] = PPM_SC_SYNC,
	[__NR_kill - SYSCALL_TABLE_ID0] = PPM_SC_KILL,
	[__NR_rename - SYSCALL_TABLE_ID0] = PPM_SC_RENAME,
	[__NR_mkdir - SYSCALL_TABLE_ID0] = PPM_SC_MKDIR,
	[__NR_rmdir - SYSCALL_TABLE_ID0] = PPM_SC_RMDIR,
	[__NR_dup - SYSCALL_TABLE_ID0] = PPM_SC_DUP,
	[__NR_pipe - SYSCALL_TABLE_ID0] = PPM_SC_PIPE,
	[__NR_times - SYSCALL_TABLE_ID0] = PPM_SC_TIMES,
	[__NR_brk - SYSCALL_TABLE_ID0] = PPM_SC_BRK,
/* [__NR_setgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETGID16, */
/* [__NR_getgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETGID16, */
/* [__NR_geteuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETEUID16, */
/* [__NR_getegid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETEGID16, */
	[__NR_acct - SYSCALL_TABLE_ID0] = PPM_SC_ACCT,
	[__NR_ioctl - SYSCALL_TABLE_ID0] = PPM_SC_IOCTL,
	[__NR_fcntl - SYSCALL_TABLE_ID0] = PPM_SC_FCNTL,
	[__NR_setpgid - SYSCALL_TABLE_ID0] = PPM_SC_SETPGID,
	[__NR_umask - SYSCALL_TABLE_ID0] = PPM_SC_UMASK,
	[__NR_chroot - SYSCALL_TABLE_ID0] = PPM_SC_CHROOT,
	[__NR_ustat - SYSCALL_TABLE_ID0] = PPM_SC_USTAT,
	[__NR_dup2 - SYSCALL_TABLE_ID0] = PPM_SC_DUP2,
	[__NR_getppid - SYSCALL_TABLE_ID0] = PPM_SC_GETPPID,
	[__NR_getpgrp - SYSCALL_TABLE_ID0] = PPM_SC_GETPGRP,
	[__NR_setsid - SYSCALL_TABLE_ID0] = PPM_SC_SETSID,
	[__NR_sethostname - SYSCALL_TABLE_ID0] = PPM_SC_SETHOSTNAME,
	[__NR_setrlimit - SYSCALL_TABLE_ID0] = PPM_SC_SETRLIMIT,
/* [__NR_old_getrlimit - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLD_GETRLIMIT, */
	[__NR_getrusage - SYSCALL_TABLE_ID0] = PPM_SC_GETRUSAGE,
	[__NR_gettimeofday - SYSCALL_TABLE_ID0] = PPM_SC_GETTIMEOFDAY,
	[__NR_settimeofday - SYSCALL_TABLE_ID0] = PPM_SC_SETTIMEOFDAY,
/* [__NR_getgroups16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETGROUPS16, */
/* [__NR_setgroups16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETGROUPS16, */
/* [__NR_old_select - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLD_SELECT, */
	[__NR_symlink - SYSCALL_TABLE_ID0] = PPM_SC_SYMLINK,
	[__NR_lstat - SYSCALL_TABLE_ID0] = PPM_SC_LSTAT,
	[__NR_readlink - SYSCALL_TABLE_ID0] = PPM_SC_READLINK,
	[__NR_uselib - SYSCALL_TABLE_ID0] = PPM_SC_USELIB,
	[__NR_swapon - SYSCALL_TABLE_ID0] = PPM_SC_SWAPON,
	[__NR_reboot - SYSCALL_TABLE_ID0] = PPM_SC_REBOOT,
/* [__NR_old_readdir - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLD_READDIR, */
/* [__NR_old_mmap - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLD_MMAP, */
#ifdef __NR_mmap
	[__NR_mmap - SYSCALL_TABLE_ID0] = PPM_SC_MMAP,
#endif
	[__NR_munmap - SYSCALL_TABLE_ID0] = PPM_SC_MUNMAP,
	[__NR_truncate - SYSCALL_TABLE_ID0] = PPM_SC_TRUNCATE,
	[__NR_ftruncate - SYSCALL_TABLE_ID0] = PPM_SC_FTRUNCATE,
	[__NR_fchmod - SYSCALL_TABLE_ID0] = PPM_SC_FCHMOD,
/* [__NR_fchown16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_FCHOWN16, */
	[__NR_getpriority - SYSCALL_TABLE_ID0] = PPM_SC_GETPRIORITY,
	[__NR_setpriority - SYSCALL_TABLE_ID0] = PPM_SC_SETPRIORITY,
	[__NR_statfs - SYSCALL_TABLE_ID0] = PPM_SC_STATFS,
	[__NR_fstatfs - SYSCALL_TABLE_ID0] = PPM_SC_FSTATFS,
	[__NR_syslog - SYSCALL_TABLE_ID0] = PPM_SC_SYSLOG,
	[__NR_setitimer - SYSCALL_TABLE_ID0] = PPM_SC_SETITIMER,
	[__NR_getitimer - SYSCALL_TABLE_ID0] = PPM_SC_GETITIMER,
/* [__NR_newstat - SYSCALL_TABLE_ID0] = PPM_SC_NR_NEWSTAT, */
/* [__NR_newlstat - SYSCALL_TABLE_ID0] = PPM_SC_NR_NEWLSTAT, */
/* [__NR_newfstat - SYSCALL_TABLE_ID0] = PPM_SC_NR_NEWFSTAT, */
	[__NR_uname - SYSCALL_TABLE_ID0] = PPM_SC_UNAME,
	[__NR_vhangup - SYSCALL_TABLE_ID0] = PPM_SC_VHANGUP,
	[__NR_wait4 - SYSCALL_TABLE_ID0] = PPM_SC_WAIT4,
	[__NR_swapoff - SYSCALL_TABLE_ID0] = PPM_SC_SWAPOFF,
	[__NR_sysinfo - SYSCALL_TABLE_ID0] = PPM_SC_SYSINFO,
	[__NR_fsync - SYSCALL_TABLE_ID0] = PPM_SC_FSYNC,
	[__NR_setdomainname - SYSCALL_TABLE_ID0] = PPM_SC_SETDOMAINNAME,
/* [__NR_newuname - SYSCALL_TABLE_ID0] = PPM_SC_NR_NEWUNAME, */
	[__NR_adjtimex - SYSCALL_TABLE_ID0] = PPM_SC_ADJTIMEX,
	[__NR_mprotect - SYSCALL_TABLE_ID0] = PPM_SC_MPROTECT,
	[__NR_init_module - SYSCALL_TABLE_ID0] = PPM_SC_INIT_MODULE,
	[__NR_delete_module - SYSCALL_TABLE_ID0] = PPM_SC_DELETE_MODULE,
	[__NR_getpgid - SYSCALL_TABLE_ID0] = PPM_SC_GETPGID,
	[__NR_fchdir - SYSCALL_TABLE_ID0] = PPM_SC_FCHDIR,
	[__NR_sysfs - SYSCALL_TABLE_ID0] = PPM_SC_SYSFS,
	[__NR_personality - SYSCALL_TABLE_ID0] = PPM_SC_PERSONALITY,
/* [__NR_setfsuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETFSUID16, */
/* [__NR_setfsgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETFSGID16, */
/* [__NR_llseek - SYSCALL_TABLE_ID0] = PPM_SC_NR_LLSEEK, */
	[__NR_getdents - SYSCALL_TABLE_ID0] = PPM_SC_GETDENTS,
#ifdef __NR_select
	[__NR_select - SYSCALL_TABLE_ID0] = PPM_SC_SELECT,
#endif
	[__NR_flock - SYSCALL_TABLE_ID0] = PPM_SC_FLOCK,
	[__NR_msync - SYSCALL_TABLE_ID0] = PPM_SC_MSYNC,
	[__NR_readv - SYSCALL_TABLE_ID0] = PPM_SC_READV,
	[__NR_writev - SYSCALL_TABLE_ID0] = PPM_SC_WRITEV,
	[__NR_getsid - SYSCALL_TABLE_ID0] = PPM_SC_GETSID,
	[__NR_fdatasync - SYSCALL_TABLE_ID0] = PPM_SC_FDATASYNC,
/* [__NR_sysctl - SYSCALL_TABLE_ID0] = PPM_SC_NR_SYSCTL, */
	[__NR_mlock - SYSCALL_TABLE_ID0] = PPM_SC_MLOCK,
	[__NR_munlock - SYSCALL_TABLE_ID0] = PPM_SC_MUNLOCK,
	[__NR_mlockall - SYSCALL_TABLE_ID0] = PPM_SC_MLOCKALL,
	[__NR_munlockall - SYSCALL_TABLE_ID0] = PPM_SC_MUNLOCKALL,
	[__NR_sched_setparam - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_SETPARAM,
	[__NR_sched_getparam - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GETPARAM,
	[__NR_sched_setscheduler - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_SETSCHEDULER,
	[__NR_sched_getscheduler - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GETSCHEDULER,
	[__NR_sched_yield - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_YIELD,
	[__NR_sched_get_priority_max - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GET_PRIORITY_MAX,
	[__NR_sched_get_priority_min - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GET_PRIORITY_MIN,
	[__NR_sched_rr_get_interval - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_RR_GET_INTERVAL,
	[__NR_nanosleep - SYSCALL_TABLE_ID0] = PPM_SC_NANOSLEEP,
	[__NR_mremap - SYSCALL_TABLE_ID0] = PPM_SC_MREMAP,
/* [__NR_setresuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETRESUID16, */
/* [__NR_getresuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETRESUID16, */
	[__NR_poll - SYSCALL_TABLE_ID0] = PPM_SC_POLL,
/* [__NR_setresgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETRESGID16, */
/* [__NR_getresgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETRESGID16, */
	[__NR_prctl - SYSCALL_TABLE_ID0] = PPM_SC_PRCTL,
#ifdef __NR_arch_prctl
	[__NR_arch_prctl - SYSCALL_TABLE_ID0] = PPM_SC_ARCH_PRCTL,
#endif
	[__NR_rt_sigaction - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGACTION,
	[__NR_rt_sigprocmask - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGPROCMASK,
	[__NR_rt_sigpending - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGPENDING,
	[__NR_rt_sigtimedwait - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGTIMEDWAIT,
	[__NR_rt_sigqueueinfo - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGQUEUEINFO,
	[__NR_rt_sigsuspend - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGSUSPEND,
/* [__NR_chown16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_CHOWN16, */
	[__NR_getcwd - SYSCALL_TABLE_ID0] = PPM_SC_GETCWD,
	[__NR_capget - SYSCALL_TABLE_ID0] = PPM_SC_CAPGET,
	[__NR_capset - SYSCALL_TABLE_ID0] = PPM_SC_CAPSET,
	[__NR_sendfile - SYSCALL_TABLE_ID0] = PPM_SC_SENDFILE,
#ifdef __NR_getrlimit
	[__NR_getrlimit - SYSCALL_TABLE_ID0] = PPM_SC_GETRLIMIT,
#endif
/* [__NR_mmap_pgoff - SYSCALL_TABLE_ID0] = PPM_SC_NR_MMAP_PGOFF, */
	[__NR_lchown - SYSCALL_TABLE_ID0] = PPM_SC_LCHOWN,
	[__NR_setreuid - SYSCALL_TABLE_ID0] = PPM_SC_SETREUID,
	[__NR_setregid - SYSCALL_TABLE_ID0] = PPM_SC_SETREGID,
	[__NR_getgroups - SYSCALL_TABLE_ID0] = PPM_SC_GETGROUPS,
	[__NR_setgroups - SYSCALL_TABLE_ID0] = PPM_SC_SETGROUPS,
	[__NR_fchown - SYSCALL_TABLE_ID0] = PPM_SC_FCHOWN,
	[__NR_chown - SYSCALL_TABLE_ID0] = PPM_SC_CHOWN,
	[__NR_setfsuid - SYSCALL_TABLE_ID0] = PPM_SC_SETFSUID,
	[__NR_setfsgid - SYSCALL_TABLE_ID0] = PPM_SC_SETFSGID,
	[__NR_pivot_root - SYSCALL_TABLE_ID0] = PPM_SC_PIVOT_ROOT,
	[__NR_mincore - SYSCALL_TABLE_ID0] = PPM_SC_MINCORE,
	[__NR_madvise - SYSCALL_TABLE_ID0] = PPM_SC_MADVISE,
	[__NR_gettid - SYSCALL_TABLE_ID0] = PPM_SC_GETTID,
	[__NR_setxattr - SYSCALL_TABLE_ID0] = PPM_SC_SETXATTR,
	[__NR_lsetxattr - SYSCALL_TABLE_ID0] = PPM_SC_LSETXATTR,
	[__NR_fsetxattr - SYSCALL_TABLE_ID0] = PPM_SC_FSETXATTR,
	[__NR_getxattr - SYSCALL_TABLE_ID0] = PPM_SC_GETXATTR,
	[__NR_lgetxattr - SYSCALL_TABLE_ID0] = PPM_SC_LGETXATTR,
	[__NR_fgetxattr - SYSCALL_TABLE_ID0] = PPM_SC_FGETXATTR,
	[__NR_listxattr - SYSCALL_TABLE_ID0] = PPM_SC_LISTXATTR,
	[__NR_llistxattr - SYSCALL_TABLE_ID0] = PPM_SC_LLISTXATTR,
	[__NR_flistxattr - SYSCALL_TABLE_ID0] = PPM_SC_FLISTXATTR,
	[__NR_removexattr - SYSCALL_TABLE_ID0] = PPM_SC_REMOVEXATTR,
	[__NR_lremovexattr - SYSCALL_TABLE_ID0] = PPM_SC_LREMOVEXATTR,
	[__NR_fremovexattr - SYSCALL_TABLE_ID0] = PPM_SC_FREMOVEXATTR,
	[__NR_tkill - SYSCALL_TABLE_ID0] = PPM_SC_TKILL,
	[__NR_futex - SYSCALL_TABLE_ID0] = PPM_SC_FUTEX,
	[__NR_sched_setaffinity - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_SETAFFINITY,
	[__NR_sched_getaffinity - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GETAFFINITY,
#ifdef __NR_set_thread_area
	[__NR_set_thread_area - SYSCALL_TABLE_ID0] = PPM_SC_SET_THREAD_AREA,
#endif
#ifdef __NR_get_thread_area
	[__NR_get_thread_area - SYSCALL_TABLE_ID0] = PPM_SC_GET_THREAD_AREA,
#endif
	[__NR_io_setup - SYSCALL_TABLE_ID0] = PPM_SC_IO_SETUP,
	[__NR_io_destroy - SYSCALL_TABLE_ID0] = PPM_SC_IO_DESTROY,
	[__NR_io_getevents - SYSCALL_TABLE_ID0] = PPM_SC_IO_GETEVENTS,
	[__NR_io_submit - SYSCALL_TABLE_ID0] = PPM_SC_IO_SUBMIT,
	[__NR_io_cancel - SYSCALL_TABLE_ID0] = PPM_SC_IO_CANCEL,
	[__NR_exit_group - SYSCALL_TABLE_ID0] = PPM_SC_EXIT_GROUP,
	[__NR_epoll_create - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_CREATE,
	[__NR_epoll_ctl - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_CTL,
	[__NR_epoll_wait - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_WAIT,
	[__NR_remap_file_pages - SYSCALL_TABLE_ID0] = PPM_SC_REMAP_FILE_PAGES,
	[__NR_set_tid_address - SYSCALL_TABLE_ID0] = PPM_SC_SET_TID_ADDRESS,
	[__NR_timer_create - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_CREATE,
	[__NR_timer_settime - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_SETTIME,
	[__NR_timer_gettime - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_GETTIME,
	[__NR_timer_getoverrun - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_GETOVERRUN,
	[__NR_timer_delete - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_DELETE,
	[__NR_clock_settime - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_SETTIME,
	[__NR_clock_gettime - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_GETTIME,
	[__NR_clock_getres - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_GETRES,
	[__NR_clock_nanosleep - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_NANOSLEEP,
	[__NR_tgkill - SYSCALL_TABLE_ID0] = PPM_SC_TGKILL,
	[__NR_utimes - SYSCALL_TABLE_ID0] = PPM_SC_UTIMES,
	[__NR_mq_open - SYSCALL_TABLE_ID0] = PPM_SC_MQ_OPEN,
	[__NR_mq_unlink - SYSCALL_TABLE_ID0] = PPM_SC_MQ_UNLINK,
	[__NR_mq_timedsend - SYSCALL_TABLE_ID0] = PPM_SC_MQ_TIMEDSEND,
	[__NR_mq_timedreceive - SYSCALL_TABLE_ID0] = PPM_SC_MQ_TIMEDRECEIVE,
	[__NR_mq_notify - SYSCALL_TABLE_ID0] = PPM_SC_MQ_NOTIFY,
	[__NR_mq_getsetattr - SYSCALL_TABLE_ID0] = PPM_SC_MQ_GETSETATTR,
	[__NR_kexec_load - SYSCALL_TABLE_ID0] = PPM_SC_KEXEC_LOAD,
	[__NR_waitid - SYSCALL_TABLE_ID0] = PPM_SC_WAITID,
	[__NR_add_key - SYSCALL_TABLE_ID0] = PPM_SC_ADD_KEY,
	[__NR_request_key - SYSCALL_TABLE_ID0] = PPM_SC_REQUEST_KEY,
	[__NR_keyctl - SYSCALL_TABLE_ID0] = PPM_SC_KEYCTL,
	[__NR_ioprio_set - SYSCALL_TABLE_ID0] = PPM_SC_IOPRIO_SET,
	[__NR_ioprio_get - SYSCALL_TABLE_ID0] = PPM_SC_IOPRIO_GET,
	[__NR_inotify_init - SYSCALL_TABLE_ID0] = PPM_SC_INOTIFY_INIT,
	[__NR_inotify_add_watch - SYSCALL_TABLE_ID0] = PPM_SC_INOTIFY_ADD_WATCH,
	[__NR_inotify_rm_watch - SYSCALL_TABLE_ID0] = PPM_SC_INOTIFY_RM_WATCH,
	[__NR_openat - SYSCALL_TABLE_ID0] = PPM_SC_OPENAT,
	[__NR_mkdirat - SYSCALL_TABLE_ID0] = PPM_SC_MKDIRAT,
	[__NR_mknodat - SYSCALL_TABLE_ID0] = PPM_SC_MKNODAT,
	[__NR_fchownat - SYSCALL_TABLE_ID0] = PPM_SC_FCHOWNAT,
	[__NR_futimesat - SYSCALL_TABLE_ID0] = PPM_SC_FUTIMESAT,
	[__NR_unlinkat - SYSCALL_TABLE_ID0] = PPM_SC_UNLINKAT,
	[__NR_renameat - SYSCALL_TABLE_ID0] = PPM_SC_RENAMEAT,
	[__NR_linkat - SYSCALL_TABLE_ID0] = PPM_SC_LINKAT,
	[__NR_symlinkat - SYSCALL_TABLE_ID0] = PPM_SC_SYMLINKAT,
	[__NR_readlinkat - SYSCALL_TABLE_ID0] = PPM_SC_READLINKAT,
	[__NR_fchmodat - SYSCALL_TABLE_ID0] = PPM_SC_FCHMODAT,
	[__NR_faccessat - SYSCALL_TABLE_ID0] = PPM_SC_FACCESSAT,
	[__NR_pselect6 - SYSCALL_TABLE_ID0] = PPM_SC_PSELECT6,
	[__NR_ppoll - SYSCALL_TABLE_ID0] = PPM_SC_PPOLL,
	[__NR_unshare - SYSCALL_TABLE_ID0] = PPM_SC_UNSHARE,
	[__NR_set_robust_list - SYSCALL_TABLE_ID0] = PPM_SC_SET_ROBUST_LIST,
	[__NR_get_robust_list - SYSCALL_TABLE_ID0] = PPM_SC_GET_ROBUST_LIST,
	[__NR_splice - SYSCALL_TABLE_ID0] = PPM_SC_SPLICE,
	[__NR_tee - SYSCALL_TABLE_ID0] = PPM_SC_TEE,
	[__NR_vmsplice - SYSCALL_TABLE_ID0] = PPM_SC_VMSPLICE,
#ifdef __NR_getcpu
	[__NR_getcpu - SYSCALL_TABLE_ID0] = PPM_SC_GETCPU,
#endif
	[__NR_epoll_pwait - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_PWAIT,
	[__NR_utimensat - SYSCALL_TABLE_ID0] = PPM_SC_UTIMENSAT,
	[__NR_signalfd - SYSCALL_TABLE_ID0] = PPM_SC_SIGNALFD,
	[__NR_timerfd_create - SYSCALL_TABLE_ID0] = PPM_SC_TIMERFD_CREATE,
	[__NR_eventfd - SYSCALL_TABLE_ID0] = PPM_SC_EVENTFD,
	[__NR_timerfd_settime - SYSCALL_TABLE_ID0] = PPM_SC_TIMERFD_SETTIME,
	[__NR_timerfd_gettime - SYSCALL_TABLE_ID0] = PPM_SC_TIMERFD_GETTIME,
	[__NR_signalfd4 - SYSCALL_TABLE_ID0] = PPM_SC_SIGNALFD4,
	[__NR_eventfd2 - SYSCALL_TABLE_ID0] = PPM_SC_EVENTFD2,
	[__NR_epoll_create1 - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_CREATE1,
	[__NR_dup3 - SYSCALL_TABLE_ID0] = PPM_SC_DUP3,
	[__NR_pipe2 - SYSCALL_TABLE_ID0] = PPM_SC_PIPE2,
	[__NR_inotify_init1 - SYSCALL_TABLE_ID0] = PPM_SC_INOTIFY_INIT1,
	[__NR_preadv - SYSCALL_TABLE_ID0] = PPM_SC_PREADV,
	[__NR_pwritev - SYSCALL_TABLE_ID0] = PPM_SC_PWRITEV,
	[__NR_rt_tgsigqueueinfo - SYSCALL_TABLE_ID0] = PPM_SC_RT_TGSIGQUEUEINFO,
	[__NR_perf_event_open - SYSCALL_TABLE_ID0] = PPM_SC_PERF_EVENT_OPEN,
#ifdef __NR_fanotify_init
	[__NR_fanotify_init - SYSCALL_TABLE_ID0] = PPM_SC_FANOTIFY_INIT,
#endif
#ifdef __NR_prlimit64
	[__NR_prlimit64 - SYSCALL_TABLE_ID0] = PPM_SC_PRLIMIT64,
#endif
#ifdef __NR_clock_adjtime
	[__NR_clock_adjtime - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_ADJTIME,
#endif
#ifdef __NR_syncfs
	[__NR_syncfs - SYSCALL_TABLE_ID0] = PPM_SC_SYNCFS,
#endif
	[__NR_getdents64 - SYSCALL_TABLE_ID0] =  PPM_SC_GETDENTS64,
#ifndef __NR_socketcall
	/*
	 * Non-multiplexed socket family
	 */
	[__NR_socket - SYSCALL_TABLE_ID0] =  PPM_SC_SOCKET,
	[__NR_bind - SYSCALL_TABLE_ID0] =	PPM_SC_BIND,
	[__NR_connect - SYSCALL_TABLE_ID0] =  PPM_SC_CONNECT,
	[__NR_listen - SYSCALL_TABLE_ID0] =  PPM_SC_LISTEN,
	[__NR_accept - SYSCALL_TABLE_ID0] =  PPM_SC_ACCEPT,
	[__NR_getsockname - SYSCALL_TABLE_ID0] = PPM_SC_GETSOCKNAME,
	[__NR_getpeername - SYSCALL_TABLE_ID0] = PPM_SC_GETPEERNAME,
	[__NR_socketpair - SYSCALL_TABLE_ID0] = PPM_SC_SOCKETPAIR,
/* [__NR_send - SYSCALL_TABLE_ID0] =	PPM_SC_NR_SEND, */
	[__NR_sendto - SYSCALL_TABLE_ID0] =  PPM_SC_SENDTO,
/* [__NR_recv - SYSCALL_TABLE_ID0] =	PPM_SC_NR_RECV, */
	[__NR_recvfrom - SYSCALL_TABLE_ID0] =  PPM_SC_RECVFROM,
	[__NR_shutdown - SYSCALL_TABLE_ID0] =  PPM_SC_SHUTDOWN,
	[__NR_setsockopt - SYSCALL_TABLE_ID0] = PPM_SC_SETSOCKOPT,
	[__NR_getsockopt - SYSCALL_TABLE_ID0] = PPM_SC_GETSOCKOPT,
	[__NR_sendmsg - SYSCALL_TABLE_ID0] =  PPM_SC_SENDMSG,
	[__NR_recvmsg - SYSCALL_TABLE_ID0] =  PPM_SC_RECVMSG,
	[__NR_accept4 - SYSCALL_TABLE_ID0] =  PPM_SC_ACCEPT4,
#else
	[__NR_socketcall - SYSCALL_TABLE_ID0] = PPM_SC_SOCKETCALL,
#endif


#ifdef __NR_sendmmsg
	[__NR_sendmmsg - SYSCALL_TABLE_ID0] =  PPM_SC_SENDMMSG,
#endif
#ifdef __NR_recvmmsg
	[__NR_recvmmsg - SYSCALL_TABLE_ID0] =  PPM_SC_RECVMMSG,
#endif
	/*
	 * Non-multiplexed IPC family
	 */
#ifdef __NR_semop
	[__NR_semop - SYSCALL_TABLE_ID0] =  PPM_SC_SEMOP,
#endif
#ifdef __NR_semget
	[__NR_semget - SYSCALL_TABLE_ID0] =  PPM_SC_SEMGET,
#endif
#ifdef __NR_semctl
	[__NR_semctl - SYSCALL_TABLE_ID0] =  PPM_SC_SEMCTL,
#endif
#ifdef __NR_msgsnd
	[__NR_msgsnd - SYSCALL_TABLE_ID0] =  PPM_SC_MSGSND,
#endif
#ifdef __NR_msgrcv
	[__NR_msgrcv - SYSCALL_TABLE_ID0] =  PPM_SC_MSGRCV,
#endif
#ifdef __NR_msgget
	[__NR_msgget - SYSCALL_TABLE_ID0] =  PPM_SC_MSGGET,
#endif
#ifdef __NR_msgctl
	[__NR_msgctl - SYSCALL_TABLE_ID0] =  PPM_SC_MSGCTL,
#endif
/* [__NR_shmatcall - SYSCALL_TABLE_ID0] =  PPM_SC_NR_SHMATCALL, */
#ifdef __NR_shmdt
	[__NR_shmdt - SYSCALL_TABLE_ID0] =  PPM_SC_SHMDT,
#endif
#ifdef __NR_shmget
	[__NR_shmget - SYSCALL_TABLE_ID0] =  PPM_SC_SHMGET,
#endif
#ifdef __NR_shmctl
	[__NR_shmctl - SYSCALL_TABLE_ID0] =  PPM_SC_SHMCTL,
#endif
/* [__NR_fcntl64 - SYSCALL_TABLE_ID0] =  PPM_SC_NR_FCNTL64, */
#ifdef __NR_statfs64
	[__NR_statfs64 - SYSCALL_TABLE_ID0] = PPM_SC_STATFS64,
#endif
#ifdef __NR_fstatfs64
	[__NR_fstatfs64 - SYSCALL_TABLE_ID0] = PPM_SC_FSTATFS64,
#endif
#ifdef __NR_fstatat64
	[__NR_fstatat64 - SYSCALL_TABLE_ID0] = PPM_SC_FSTATAT64,
#endif
#ifdef __NR_sendfile64
	[__NR_sendfile64 - SYSCALL_TABLE_ID0] = PPM_SC_SENDFILE64,
#endif
#ifdef __NR_ugetrlimit
	[__NR_ugetrlimit - SYSCALL_TABLE_ID0] = PPM_SC_UGETRLIMIT,
#endif
#ifdef __NR_bdflush
	[__NR_bdflush - SYSCALL_TABLE_ID0] = PPM_SC_BDFLUSH,
#endif
#ifdef __NR_sigprocmask
	[__NR_sigprocmask - SYSCALL_TABLE_ID0] = PPM_SC_SIGPROCMASK,
#endif
#ifdef __NR_ipc
	[__NR_ipc - SYSCALL_TABLE_ID0] = PPM_SC_IPC,
#endif
#ifdef __NR_stat64
	[__NR_stat64 - SYSCALL_TABLE_ID0] = PPM_SC_STAT64,
#endif
#ifdef __NR_lstat64
	[__NR_lstat64 - SYSCALL_TABLE_ID0] = PPM_SC_LSTAT64,
#endif
#ifdef __NR_fstat64
	[__NR_fstat64 - SYSCALL_TABLE_ID0] = PPM_SC_FSTAT64,
#endif
#ifdef __NR_fcntl64
	[__NR_fcntl64 - SYSCALL_TABLE_ID0] = PPM_SC_FCNTL64,
#endif
#ifdef __NR_mmap2
	[__NR_mmap2 - SYSCALL_TABLE_ID0] = PPM_SC_MMAP2,
#endif
#ifdef __NR__newselect
	[__NR__newselect - SYSCALL_TABLE_ID0] = PPM_SC__NEWSELECT,
#endif
#ifdef __NR_sgetmask
	[__NR_sgetmask - SYSCALL_TABLE_ID0] = PPM_SC_SGETMASK,
#endif
#ifdef __NR_ssetmask
	[__NR_ssetmask - SYSCALL_TABLE_ID0] = PPM_SC_SSETMASK,
#endif

/* [__NR_setreuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETREUID16, */
/* [__NR_setregid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETREGID16, */
#ifdef __NR_sigpending
	[__NR_sigpending - SYSCALL_TABLE_ID0] = PPM_SC_SIGPENDING,
#endif
#ifdef __NR_olduname
	[__NR_olduname - SYSCALL_TABLE_ID0] = PPM_SC_OLDUNAME,
#endif
#ifdef __NR_umount
	[__NR_umount - SYSCALL_TABLE_ID0] = PPM_SC_UMOUNT,
#endif
#ifdef __NR_signal
	[__NR_signal - SYSCALL_TABLE_ID0] = PPM_SC_SIGNAL,
#endif
#ifdef __NR_nice
	[__NR_nice - SYSCALL_TABLE_ID0] = PPM_SC_NICE,
#endif
#ifdef __NR_stime
	[__NR_stime - SYSCALL_TABLE_ID0] = PPM_SC_STIME,
#endif
#ifdef __NR__llseek
	[__NR__llseek - SYSCALL_TABLE_ID0] = PPM_SC__LLSEEK,
#endif
#ifdef __NR_waitpid
	[__NR_waitpid - SYSCALL_TABLE_ID0] = PPM_SC_WAITPID,
#endif
#ifdef __NR_pread64
	[__NR_pread64 - SYSCALL_TABLE_ID0] = PPM_SC_PREAD64,
#endif
#ifdef __NR_pwrite64
	[__NR_pwrite64 - SYSCALL_TABLE_ID0] = PPM_SC_PWRITE64,
#endif
#ifdef __NR_shmat
	[__NR_shmat - SYSCALL_TABLE_ID0] = PPM_SC_SHMAT,
#endif
#ifdef __NR_rt_sigreturn
	[__NR_rt_sigreturn - SYSCALL_TABLE_ID0] = PPM_SC_SIGRETURN,
#endif
#ifdef __NR_fallocate
	[__NR_fallocate - SYSCALL_TABLE_ID0] = PPM_SC_FALLOCATE,
#endif
#ifdef __NR_newfstatat
	[__NR_newfstatat - SYSCALL_TABLE_ID0] = PPM_SC_NEWFSSTAT,
#endif
#ifdef __NR_process_vm_readv
	[__NR_process_vm_readv - SYSCALL_TABLE_ID0] = PPM_SC_PROCESS_VM_READV,
#endif
#ifdef __NR_process_vm_writev
	[__NR_process_vm_writev - SYSCALL_TABLE_ID0] = PPM_SC_PROCESS_VM_WRITEV,
#endif
#ifdef __NR_fork
	[__NR_fork - SYSCALL_TABLE_ID0] = PPM_SC_FORK,
#endif
#ifdef __NR_vfork
	[__NR_vfork - SYSCALL_TABLE_ID0] = PPM_SC_VFORK,
#endif
#ifdef __NR_quotactl
	[__NR_quotactl - SYSCALL_TABLE_ID0] = PPM_SC_QUOTACTL,
#endif
#ifdef __NR_setresuid
	[__NR_setresuid - SYSCALL_TABLE_ID0] = PPM_SC_SETRESUID,
#endif
#ifdef __NR_setresuid32
	[__NR_setresuid32 - SYSCALL_TABLE_ID0] = PPM_SC_SETRESUID,
#endif
#ifdef __NR_setresgid
	[__NR_setresgid - SYSCALL_TABLE_ID0] = PPM_SC_SETRESGID,
#endif
#ifdef __NR_setresgid32
	[__NR_setresgid32 - SYSCALL_TABLE_ID0] = PPM_SC_SETRESGID,
#endif
#ifdef __NR_setuid
	[__NR_setuid - SYSCALL_TABLE_ID0] = PPM_SC_SETUID,
#endif
#ifdef __NR_setuid32
	[__NR_setuid32 - SYSCALL_TABLE_ID0] = PPM_SC_SETUID32,
#endif
#ifdef __NR_setgid
	[__NR_setgid - SYSCALL_TABLE_ID0] = PPM_SC_SETGID,
#endif
#ifdef __NR_setgid32
	[__NR_setgid32 - SYSCALL_TABLE_ID0] = PPM_SC_SETGID32,
#endif
#ifdef __NR_getuid
	[__NR_getuid - SYSCALL_TABLE_ID0] = PPM_SC_GETUID,
#endif
#ifdef __NR_getuid32
	[__NR_getuid32 - SYSCALL_TABLE_ID0] = PPM_SC_GETUID32,
#endif
#ifdef __NR_geteuid
	[__NR_geteuid - SYSCALL_TABLE_ID0] = PPM_SC_GETEUID,
#endif
#ifdef __NR_geteuid32
	[__NR_geteuid32 - SYSCALL_TABLE_ID0] = PPM_SC_GETEUID,
#endif
#ifdef __NR_getgid
	[__NR_getgid - SYSCALL_TABLE_ID0] = PPM_SC_GETGID,
#endif
#ifdef __NR_getgid32
	[__NR_getgid32 - SYSCALL_TABLE_ID0] = PPM_SC_GETGID,
#endif
#ifdef __NR_getegid
	[__NR_getegid - SYSCALL_TABLE_ID0] = PPM_SC_GETEGID,
#endif
#ifdef __NR_getegid32
	[__NR_getegid32 - SYSCALL_TABLE_ID0] = PPM_SC_GETEGID,
#endif
#ifdef __NR_getresuid
	[__NR_getresuid - SYSCALL_TABLE_ID0] = PPM_SC_GETRESUID,
#endif
#ifdef __NR_getresuid32
	[__NR_getresuid32 - SYSCALL_TABLE_ID0] = PPM_SC_GETRESUID32,
#endif
#ifdef __NR_getresgid
	[__NR_getresgid - SYSCALL_TABLE_ID0] = PPM_SC_GETRESGID,
#endif
#ifdef __NR_getresgid32
	[__NR_getresgid32 - SYSCALL_TABLE_ID0] = PPM_SC_GETRESGID32,
#endif
#ifdef __NR_setns
	[__NR_setns - SYSCALL_TABLE_ID0] = PPM_SC_SETNS,
#endif
#ifdef __NR_access
	[__NR_access - SYSCALL_TABLE_ID0] = PPM_SC_ACCESS,
#endif
#ifdef __NR_finit_module
	[__NR_finit_module - SYSCALL_TABLE_ID0] = PPM_SC_FINIT_MODULE,
#endif
#ifdef __NR_bpf
	[__NR_bpf - SYSCALL_TABLE_ID0] = PPM_SC_BPF,
#endif
#ifdef __NR_seccomp
	[__NR_seccomp - SYSCALL_TABLE_ID0] = PPM_SC_SECCOMP,
#endif
#ifdef __NR_sigaltstack
	[__NR_sigaltstack - SYSCALL_TABLE_ID0] = PPM_SC_SIGALTSTACK,
#endif
#ifdef __NR_getrandom
	[__NR_getrandom - SYSCALL_TABLE_ID0] = PPM_SC_GETRANDOM,
#endif
#ifdef __NR_fadvise64
	[__NR_fadvise64 - SYSCALL_TABLE_ID0] = PPM_SC_FADVISE64,
#endif
};

#ifdef CONFIG_IA32_EMULATION
const struct syscall_evt_pair g_syscall_ia32_table[SYSCALL_TABLE_SIZE] = {
	[__NR_ia32_open - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_OPEN_E, PPME_SYSCALL_OPEN_X},
	[__NR_ia32_creat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CREAT_E, PPME_SYSCALL_CREAT_X},
	[__NR_ia32_close - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X},
	[__NR_ia32_brk - SYSCALL_TABLE_ID0] =                        {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_BRK_4_E, PPME_SYSCALL_BRK_4_X},
	[__NR_ia32_read - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_READ_E, PPME_SYSCALL_READ_X},
	[__NR_ia32_write - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_WRITE_E, PPME_SYSCALL_WRITE_X},
	[__NR_ia32_execve - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_EXECVE_19_E, PPME_SYSCALL_EXECVE_19_X},
	[__NR_ia32_clone - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_CLONE_20_E, PPME_SYSCALL_CLONE_20_X},
	[__NR_ia32_fork - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_FORK_20_E, PPME_SYSCALL_FORK_20_X},
	[__NR_ia32_vfork - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_VFORK_20_E, PPME_SYSCALL_VFORK_20_X},
	[__NR_ia32_pipe - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PIPE_E, PPME_SYSCALL_PIPE_X},
	[__NR_ia32_pipe2 - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PIPE_E, PPME_SYSCALL_PIPE_X},
	[__NR_ia32_eventfd - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X},
	[__NR_ia32_eventfd2 - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X},
	[__NR_ia32_futex - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FUTEX_E, PPME_SYSCALL_FUTEX_X},
	[__NR_ia32_stat - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_STAT_E, PPME_SYSCALL_STAT_X},
	[__NR_ia32_lstat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_LSTAT_E, PPME_SYSCALL_LSTAT_X},
	[__NR_ia32_fstat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FSTAT_E, PPME_SYSCALL_FSTAT_X},
	[__NR_ia32_epoll_wait - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_EPOLLWAIT_E, PPME_SYSCALL_EPOLLWAIT_X},
	[__NR_ia32_poll - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_POLL_E, PPME_SYSCALL_POLL_X},
#ifdef __NR_ia32_select
	[__NR_ia32_select - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SELECT_E, PPME_SYSCALL_SELECT_X},
#endif
	[__NR_ia32_lseek - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_LSEEK_E, PPME_SYSCALL_LSEEK_X},
	[__NR_ia32_ioctl - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_IOCTL_3_E, PPME_SYSCALL_IOCTL_3_X},
	[__NR_ia32_getcwd - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_GETCWD_E, PPME_SYSCALL_GETCWD_X},
	[__NR_ia32_chdir - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_CHDIR_E, PPME_SYSCALL_CHDIR_X},
	[__NR_ia32_fchdir - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_FCHDIR_E, PPME_SYSCALL_FCHDIR_X},
	[__NR_ia32_mkdir - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_MKDIR_2_E, PPME_SYSCALL_MKDIR_2_X},
	[__NR_ia32_rmdir - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_RMDIR_2_E, PPME_SYSCALL_RMDIR_2_X},
	[__NR_ia32_openat - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X},
	[__NR_ia32_mkdirat - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_MKDIRAT_E, PPME_SYSCALL_MKDIRAT_X},
	[__NR_ia32_link - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_LINK_2_E, PPME_SYSCALL_LINK_2_X},
	[__NR_ia32_linkat - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_LINKAT_2_E, PPME_SYSCALL_LINKAT_2_X},
	[__NR_ia32_unlink - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_UNLINK_2_E, PPME_SYSCALL_UNLINK_2_X},
	[__NR_ia32_unlinkat - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_UNLINKAT_2_E, PPME_SYSCALL_UNLINKAT_2_X},
	[__NR_ia32_pread64 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_PREAD_E, PPME_SYSCALL_PREAD_X},
	[__NR_ia32_pwrite64 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_PWRITE_E, PPME_SYSCALL_PWRITE_X},
	[__NR_ia32_readv - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_READV_E, PPME_SYSCALL_READV_X},
	[__NR_ia32_writev - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_WRITEV_E, PPME_SYSCALL_WRITEV_X},
	[__NR_ia32_preadv - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_PREADV_E, PPME_SYSCALL_PREADV_X},
	[__NR_ia32_pwritev - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_PWRITEV_E, PPME_SYSCALL_PWRITEV_X},
	[__NR_ia32_dup - SYSCALL_TABLE_ID0] =                        {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_ia32_dup2 - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_ia32_dup3 - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_ia32_signalfd - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SIGNALFD_E, PPME_SYSCALL_SIGNALFD_X},
	[__NR_ia32_signalfd4 - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SIGNALFD_E, PPME_SYSCALL_SIGNALFD_X},
	[__NR_ia32_kill - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_KILL_E, PPME_SYSCALL_KILL_X},
	[__NR_ia32_tkill - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_TKILL_E, PPME_SYSCALL_TKILL_X},
	[__NR_ia32_tgkill - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_TGKILL_E, PPME_SYSCALL_TGKILL_X},
	[__NR_ia32_nanosleep - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_NANOSLEEP_E, PPME_SYSCALL_NANOSLEEP_X},
	[__NR_ia32_timerfd_create - SYSCALL_TABLE_ID0] =             {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_TIMERFD_CREATE_E, PPME_SYSCALL_TIMERFD_CREATE_X},
	[__NR_ia32_inotify_init - SYSCALL_TABLE_ID0] =               {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_INOTIFY_INIT_E, PPME_SYSCALL_INOTIFY_INIT_X},
	[__NR_ia32_inotify_init1 - SYSCALL_TABLE_ID0] =              {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_INOTIFY_INIT_E, PPME_SYSCALL_INOTIFY_INIT_X},
	[__NR_ia32_getrlimit - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_GETRLIMIT_E, PPME_SYSCALL_GETRLIMIT_X},
	[__NR_ia32_setrlimit - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SETRLIMIT_E, PPME_SYSCALL_SETRLIMIT_X},
	[__NR_ia32_fchmodat - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_FCHMODAT_E, PPME_SYSCALL_FCHMODAT_X},
	[__NR_ia32_fchmod - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_FCHMOD_E, PPME_SYSCALL_FCHMOD_X},
#ifdef __NR_ia32_prlimit64
	[__NR_ia32_prlimit64 - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PRLIMIT_E, PPME_SYSCALL_PRLIMIT_X},
#endif
#ifdef __NR_ia32_ugetrlimit
	[__NR_ia32_ugetrlimit - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_GETRLIMIT_E, PPME_SYSCALL_GETRLIMIT_X},
#endif
	[__NR_ia32_fcntl - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_FCNTL_E, PPME_SYSCALL_FCNTL_X},
#ifdef __NR_ia32_fcntl64
	[__NR_ia32_fcntl64 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_FCNTL_E, PPME_SYSCALL_FCNTL_X},
#endif
	[__NR_ia32_ppoll - SYSCALL_TABLE_ID0] =			             {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_PPOLL_E, PPME_SYSCALL_PPOLL_X},
/* [__NR_ia32_old_select - SYSCALL_TABLE_ID0] =	{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X}, */
	[__NR_ia32_pselect6 - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_ia32_epoll_create - SYSCALL_TABLE_ID0] =               {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_ia32_epoll_ctl - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_ia32_uselib - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_ia32_sched_setparam - SYSCALL_TABLE_ID0] =             {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_ia32_sched_getparam - SYSCALL_TABLE_ID0] =             {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_ia32_syslog - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_ia32_chmod - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_CHMOD_E, PPME_SYSCALL_CHMOD_X},
	[__NR_ia32_lchown - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_ia32_utime - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_ia32_mount - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_ia32_umount2 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_ia32_ptrace - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_PTRACE_E, PPME_SYSCALL_PTRACE_X},
	[__NR_ia32_alarm - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_ia32_pause - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_GENERIC_E, PPME_GENERIC_X},

#ifndef __NR_ia32_socketcall
	[__NR_ia32_socket - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_SIMPLEDRIVER_KEEP, PPME_SOCKET_SOCKET_E, PPME_SOCKET_SOCKET_X},
	[__NR_ia32_bind - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SOCKET_BIND_E,  PPME_SOCKET_BIND_X},
	[__NR_ia32_connect - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_SIMPLEDRIVER_KEEP, PPME_SOCKET_CONNECT_E, PPME_SOCKET_CONNECT_X},
	[__NR_ia32_listen - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SOCKET_LISTEN_E, PPME_SOCKET_LISTEN_X},
	[__NR_ia32_accept - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_SIMPLEDRIVER_KEEP, PPME_SOCKET_ACCEPT_E, PPME_SOCKET_ACCEPT_X},
	[__NR_ia32_getsockname - SYSCALL_TABLE_ID0] =                {UF_USED | UF_ALWAYS_DROP, PPME_SOCKET_GETSOCKNAME_E, PPME_SOCKET_GETSOCKNAME_X},
	[__NR_ia32_getpeername - SYSCALL_TABLE_ID0] =                {UF_USED | UF_ALWAYS_DROP, PPME_SOCKET_GETPEERNAME_E, PPME_SOCKET_GETPEERNAME_X},
	[__NR_ia32_socketpair - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_NEVER_DROP, PPME_SOCKET_SOCKETPAIR_E, PPME_SOCKET_SOCKETPAIR_X},
	[__NR_ia32_sendto - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SOCKET_SENDTO_E, PPME_SOCKET_SENDTO_X},
	[__NR_ia32_recvfrom - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_RECVFROM_E, PPME_SOCKET_RECVFROM_X},
	[__NR_ia32_shutdown - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_SHUTDOWN_E, PPME_SOCKET_SHUTDOWN_X},
	[__NR_ia32_setsockopt - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_ALWAYS_DROP, PPME_SOCKET_SETSOCKOPT_E, PPME_SOCKET_SETSOCKOPT_X},
	[__NR_ia32_getsockopt - SYSCALL_TABLE_ID0] =                 {UF_USED, PPME_SOCKET_GETSOCKOPT_E, PPME_SOCKET_GETSOCKOPT_X},
	[__NR_ia32_sendmsg - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SOCKET_SENDMSG_E, PPME_SOCKET_SENDMSG_X},
	[__NR_ia32_accept4 - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_SIMPLEDRIVER_KEEP, PPME_SOCKET_ACCEPT4_E, PPME_SOCKET_ACCEPT4_X},
#endif

#ifdef __NR_ia32_sendmmsg
	[__NR_ia32_sendmmsg - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_SENDMMSG_E, PPME_SOCKET_SENDMMSG_X},
#endif
#ifdef __NR_ia32_recvmsg
	[__NR_ia32_recvmsg - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SOCKET_RECVMSG_E, PPME_SOCKET_RECVMSG_X},
#endif
#ifdef __NR_ia32_recvmmsg
	[__NR_ia32_recvmmsg - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_RECVMMSG_E, PPME_SOCKET_RECVMMSG_X},
#endif
#ifdef __NR_ia32_stat64
	[__NR_ia32_stat64 - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_STAT64_E, PPME_SYSCALL_STAT64_X},
#endif
#ifdef __NR_ia32_fstat64
	[__NR_ia32_fstat64 - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FSTAT64_E, PPME_SYSCALL_FSTAT64_X},
#endif
#ifdef __NR_ia32__llseek
	[__NR_ia32__llseek - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_LLSEEK_E, PPME_SYSCALL_LLSEEK_X},
#endif
	[__NR_ia32_mmap - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_MMAP_E, PPME_SYSCALL_MMAP_X},
#ifdef __NR_ia32_mmap2
	[__NR_ia32_mmap2 - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_MMAP2_E, PPME_SYSCALL_MMAP2_X},
#endif
	[__NR_ia32_munmap - SYSCALL_TABLE_ID0] =						{UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_MUNMAP_E, PPME_SYSCALL_MUNMAP_X},
	[__NR_ia32_splice - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_SPLICE_E, PPME_SYSCALL_SPLICE_X},
#ifdef __NR_ia32_process_vm_readv
	[__NR_ia32_process_vm_readv - SYSCALL_TABLE_ID0] =           {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
#endif
#ifdef __NR_ia32_process_vm_writev
	[__NR_ia32_process_vm_writev - SYSCALL_TABLE_ID0] =          {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
#endif

	[__NR_ia32_rename - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_RENAME_E, PPME_SYSCALL_RENAME_X},
	[__NR_ia32_renameat - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_RENAMEAT_E, PPME_SYSCALL_RENAMEAT_X},
	[__NR_ia32_symlink - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_SYMLINK_E, PPME_SYSCALL_SYMLINK_X},
	[__NR_ia32_symlinkat - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_SYMLINKAT_E, PPME_SYSCALL_SYMLINKAT_X},
	[__NR_ia32_sendfile - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_SENDFILE_E, PPME_SYSCALL_SENDFILE_X},
#ifdef __NR_ia32_sendfile64
	[__NR_ia32_sendfile64 - SYSCALL_TABLE_ID0] =                 {UF_USED, PPME_SYSCALL_SENDFILE_E, PPME_SYSCALL_SENDFILE_X},
#endif
#ifdef __NR_ia32_quotactl
	[__NR_ia32_quotactl - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_QUOTACTL_E, PPME_SYSCALL_QUOTACTL_X},
#endif
#ifdef __NR_ia32_setresuid
	[__NR_ia32_setresuid - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_SETRESUID_E, PPME_SYSCALL_SETRESUID_X },
#endif
#ifdef __NR_ia32_setresuid32
	[__NR_ia32_setresuid32 - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_SETRESUID_E, PPME_SYSCALL_SETRESUID_X },
#endif
#ifdef __NR_ia32_setresgid
	[__NR_ia32_setresgid - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_SETRESGID_E, PPME_SYSCALL_SETRESGID_X },
#endif
#ifdef __NR_ia32_setresgid32
	[__NR_ia32_setresgid32 - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_SETRESGID_E, PPME_SYSCALL_SETRESGID_X },
#endif
#ifdef __NR_ia32_setuid
	[__NR_ia32_setuid - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_SETUID_E, PPME_SYSCALL_SETUID_X },
#endif
#ifdef __NR_ia32_setuid32
	[__NR_ia32_setuid32 - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_SETUID_E, PPME_SYSCALL_SETUID_X },
#endif
#ifdef __NR_ia32_setgid
	[__NR_ia32_setgid - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_SETGID_E, PPME_SYSCALL_SETGID_X },
#endif
#ifdef __NR_ia32_setgid32
	[__NR_ia32_setgid32 - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_SETGID_E, PPME_SYSCALL_SETGID_X },
#endif
#ifdef __NR_ia32_getuid
	[__NR_ia32_getuid - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_GETUID_E, PPME_SYSCALL_GETUID_X },
#endif
#ifdef __NR_ia32_getuid32
	[__NR_ia32_getuid32 - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_GETUID_E, PPME_SYSCALL_GETUID_X },
#endif
#ifdef __NR_ia32_geteuid
	[__NR_ia32_geteuid - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_GETEUID_E, PPME_SYSCALL_GETEUID_X },
#endif
#ifdef __NR_ia32_geteuid32
	[__NR_ia32_geteuid32 - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_GETEUID_E, PPME_SYSCALL_GETEUID_X },
#endif
#ifdef __NR_ia32_getgid
	[__NR_ia32_getgid - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_GETGID_E, PPME_SYSCALL_GETGID_X },
#endif
#ifdef __NR_ia32_getgid32
	[__NR_ia32_getgid32 - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_GETGID_E, PPME_SYSCALL_GETGID_X },
#endif
#ifdef __NR_ia32_getegid
	[__NR_ia32_getegid - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_GETEGID_E, PPME_SYSCALL_GETEGID_X },
#endif
#ifdef __NR_ia32_getegid32
	[__NR_ia32_getegid32 - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_GETEGID_E, PPME_SYSCALL_GETEGID_X },
#endif
#ifdef __NR_ia32_getresuid
	[__NR_ia32_getresuid - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_GETRESUID_E, PPME_SYSCALL_GETRESUID_X },
#endif
#ifdef __NR_ia32_getresuid32
	[__NR_ia32_getresuid32 - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_GETRESUID_E, PPME_SYSCALL_GETRESUID_X },
#endif
#ifdef __NR_ia32_getresgid
	[__NR_ia32_getresgid - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_GETRESGID_E, PPME_SYSCALL_GETRESGID_X },
#endif
#ifdef __NR_ia32_getresgid32
	[__NR_ia32_getresgid32 - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_GETRESGID_E, PPME_SYSCALL_GETRESGID_X },
#endif
#ifdef __NR_ia32_semop
	[__NR_ia32_semop - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SEMOP_E, PPME_SYSCALL_SEMOP_X},
#endif
#ifdef __NR_ia32_semget
	[__NR_ia32_semget - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SEMGET_E, PPME_SYSCALL_SEMGET_X},
#endif
#ifdef __NR_ia32_semctl
	[__NR_ia32_semctl - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SEMCTL_E, PPME_SYSCALL_SEMCTL_X},
#endif
#ifdef __NR_ia32_access
	[__NR_ia32_access - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_ACCESS_E, PPME_SYSCALL_ACCESS_X},
#endif
#ifdef __NR_ia32_chroot
	[__NR_ia32_chroot - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CHROOT_E, PPME_SYSCALL_CHROOT_X},
#endif
	[__NR_ia32_setsid - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SETSID_E, PPME_SYSCALL_SETSID_X},
	[__NR_ia32_setpgid - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SETPGID_E, PPME_SYSCALL_SETPGID_X},
#ifdef __NR_ia32_bpf
	[__NR_ia32_bpf - SYSCALL_TABLE_ID0] =                        {UF_USED, PPME_SYSCALL_BPF_E, PPME_SYSCALL_BPF_X},
#endif
#ifdef __NR_ia32_seccomp
	[__NR_ia32_seccomp - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_SECCOMP_E, PPME_SYSCALL_SECCOMP_X},
#endif
};

/*
 * SYSCALL ROUTING TABLE
 */
const enum ppm_syscall_code g_syscall_ia32_code_routing_table[SYSCALL_TABLE_SIZE] = {
	[__NR_ia32_restart_syscall - SYSCALL_TABLE_ID0] = PPM_SC_RESTART_SYSCALL,
	[__NR_ia32_exit - SYSCALL_TABLE_ID0] = PPM_SC_EXIT,
	[__NR_ia32_read - SYSCALL_TABLE_ID0] = PPM_SC_READ,
	[__NR_ia32_write - SYSCALL_TABLE_ID0] = PPM_SC_WRITE,
	[__NR_ia32_open - SYSCALL_TABLE_ID0] = PPM_SC_OPEN,
	[__NR_ia32_close - SYSCALL_TABLE_ID0] = PPM_SC_CLOSE,
	[__NR_ia32_creat - SYSCALL_TABLE_ID0] = PPM_SC_CREAT,
	[__NR_ia32_link - SYSCALL_TABLE_ID0] = PPM_SC_LINK,
	[__NR_ia32_unlink - SYSCALL_TABLE_ID0] = PPM_SC_UNLINK,
	[__NR_ia32_chdir - SYSCALL_TABLE_ID0] = PPM_SC_CHDIR,
	[__NR_ia32_time - SYSCALL_TABLE_ID0] = PPM_SC_TIME,
	[__NR_ia32_mknod - SYSCALL_TABLE_ID0] = PPM_SC_MKNOD,
	[__NR_ia32_chmod - SYSCALL_TABLE_ID0] = PPM_SC_CHMOD,
/* [__NR_ia32_lchown16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_LCHOWN16, */
	[__NR_ia32_stat - SYSCALL_TABLE_ID0] = PPM_SC_STAT,
	[__NR_ia32_lseek - SYSCALL_TABLE_ID0] = PPM_SC_LSEEK,
	[__NR_ia32_getpid - SYSCALL_TABLE_ID0] = PPM_SC_GETPID,
	[__NR_ia32_mount - SYSCALL_TABLE_ID0] = PPM_SC_MOUNT,
/* [__NR_ia32_oldumount - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLDUMOUNT, */
/* [__NR_ia32_setuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETUID16, */
/* [__NR_ia32_getuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETUID16, */
	[__NR_ia32_ptrace - SYSCALL_TABLE_ID0] = PPM_SC_PTRACE,
	[__NR_ia32_alarm - SYSCALL_TABLE_ID0] = PPM_SC_ALARM,
	[__NR_ia32_fstat - SYSCALL_TABLE_ID0] = PPM_SC_FSTAT,
	[__NR_ia32_pause - SYSCALL_TABLE_ID0] = PPM_SC_PAUSE,
	[__NR_ia32_utime - SYSCALL_TABLE_ID0] = PPM_SC_UTIME,
	[__NR_ia32_access - SYSCALL_TABLE_ID0] = PPM_SC_ACCESS,
	[__NR_ia32_sync - SYSCALL_TABLE_ID0] = PPM_SC_SYNC,
	[__NR_ia32_kill - SYSCALL_TABLE_ID0] = PPM_SC_KILL,
	[__NR_ia32_rename - SYSCALL_TABLE_ID0] = PPM_SC_RENAME,
	[__NR_ia32_mkdir - SYSCALL_TABLE_ID0] = PPM_SC_MKDIR,
	[__NR_ia32_rmdir - SYSCALL_TABLE_ID0] = PPM_SC_RMDIR,
	[__NR_ia32_dup - SYSCALL_TABLE_ID0] = PPM_SC_DUP,
	[__NR_ia32_pipe - SYSCALL_TABLE_ID0] = PPM_SC_PIPE,
	[__NR_ia32_times - SYSCALL_TABLE_ID0] = PPM_SC_TIMES,
	[__NR_ia32_brk - SYSCALL_TABLE_ID0] = PPM_SC_BRK,
/* [__NR_ia32_setgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETGID16, */
/* [__NR_ia32_getgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETGID16, */
/* [__NR_ia32_geteuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETEUID16, */
/* [__NR_ia32_getegid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETEGID16, */
	[__NR_ia32_acct - SYSCALL_TABLE_ID0] = PPM_SC_ACCT,
	[__NR_ia32_ioctl - SYSCALL_TABLE_ID0] = PPM_SC_IOCTL,
	[__NR_ia32_fcntl - SYSCALL_TABLE_ID0] = PPM_SC_FCNTL,
	[__NR_ia32_setpgid - SYSCALL_TABLE_ID0] = PPM_SC_SETPGID,
	[__NR_ia32_umask - SYSCALL_TABLE_ID0] = PPM_SC_UMASK,
	[__NR_ia32_chroot - SYSCALL_TABLE_ID0] = PPM_SC_CHROOT,
	[__NR_ia32_ustat - SYSCALL_TABLE_ID0] = PPM_SC_USTAT,
	[__NR_ia32_dup2 - SYSCALL_TABLE_ID0] = PPM_SC_DUP2,
	[__NR_ia32_getppid - SYSCALL_TABLE_ID0] = PPM_SC_GETPPID,
	[__NR_ia32_getpgrp - SYSCALL_TABLE_ID0] = PPM_SC_GETPGRP,
	[__NR_ia32_setsid - SYSCALL_TABLE_ID0] = PPM_SC_SETSID,
	[__NR_ia32_sethostname - SYSCALL_TABLE_ID0] = PPM_SC_SETHOSTNAME,
	[__NR_ia32_setrlimit - SYSCALL_TABLE_ID0] = PPM_SC_SETRLIMIT,
/* [__NR_ia32_old_getrlimit - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLD_GETRLIMIT, */
	[__NR_ia32_getrusage - SYSCALL_TABLE_ID0] = PPM_SC_GETRUSAGE,
	[__NR_ia32_gettimeofday - SYSCALL_TABLE_ID0] = PPM_SC_GETTIMEOFDAY,
	[__NR_ia32_settimeofday - SYSCALL_TABLE_ID0] = PPM_SC_SETTIMEOFDAY,
/* [__NR_ia32_getgroups16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETGROUPS16, */
/* [__NR_ia32_setgroups16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETGROUPS16, */
/* [__NR_ia32_old_select - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLD_SELECT, */
	[__NR_ia32_symlink - SYSCALL_TABLE_ID0] = PPM_SC_SYMLINK,
	[__NR_ia32_lstat - SYSCALL_TABLE_ID0] = PPM_SC_LSTAT,
	[__NR_ia32_readlink - SYSCALL_TABLE_ID0] = PPM_SC_READLINK,
	[__NR_ia32_uselib - SYSCALL_TABLE_ID0] = PPM_SC_USELIB,
	[__NR_ia32_swapon - SYSCALL_TABLE_ID0] = PPM_SC_SWAPON,
	[__NR_ia32_reboot - SYSCALL_TABLE_ID0] = PPM_SC_REBOOT,
/* [__NR_ia32_old_readdir - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLD_READDIR, */
/* [__NR_ia32_old_mmap - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLD_MMAP, */
	[__NR_ia32_mmap - SYSCALL_TABLE_ID0] = PPM_SC_MMAP,
	[__NR_ia32_munmap - SYSCALL_TABLE_ID0] = PPM_SC_MUNMAP,
	[__NR_ia32_truncate - SYSCALL_TABLE_ID0] = PPM_SC_TRUNCATE,
	[__NR_ia32_ftruncate - SYSCALL_TABLE_ID0] = PPM_SC_FTRUNCATE,
	[__NR_ia32_fchmod - SYSCALL_TABLE_ID0] = PPM_SC_FCHMOD,
/* [__NR_ia32_fchown16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_FCHOWN16, */
	[__NR_ia32_getpriority - SYSCALL_TABLE_ID0] = PPM_SC_GETPRIORITY,
	[__NR_ia32_setpriority - SYSCALL_TABLE_ID0] = PPM_SC_SETPRIORITY,
	[__NR_ia32_statfs - SYSCALL_TABLE_ID0] = PPM_SC_STATFS,
	[__NR_ia32_fstatfs - SYSCALL_TABLE_ID0] = PPM_SC_FSTATFS,
	[__NR_ia32_syslog - SYSCALL_TABLE_ID0] = PPM_SC_SYSLOG,
	[__NR_ia32_setitimer - SYSCALL_TABLE_ID0] = PPM_SC_SETITIMER,
	[__NR_ia32_getitimer - SYSCALL_TABLE_ID0] = PPM_SC_GETITIMER,
/* [__NR_ia32_newstat - SYSCALL_TABLE_ID0] = PPM_SC_NR_NEWSTAT, */
/* [__NR_ia32_newlstat - SYSCALL_TABLE_ID0] = PPM_SC_NR_NEWLSTAT, */
/* [__NR_ia32_newfstat - SYSCALL_TABLE_ID0] = PPM_SC_NR_NEWFSTAT, */
	[__NR_ia32_uname - SYSCALL_TABLE_ID0] = PPM_SC_UNAME,
	[__NR_ia32_vhangup - SYSCALL_TABLE_ID0] = PPM_SC_VHANGUP,
	[__NR_ia32_wait4 - SYSCALL_TABLE_ID0] = PPM_SC_WAIT4,
	[__NR_ia32_swapoff - SYSCALL_TABLE_ID0] = PPM_SC_SWAPOFF,
	[__NR_ia32_sysinfo - SYSCALL_TABLE_ID0] = PPM_SC_SYSINFO,
	[__NR_ia32_fsync - SYSCALL_TABLE_ID0] = PPM_SC_FSYNC,
	[__NR_ia32_setdomainname - SYSCALL_TABLE_ID0] = PPM_SC_SETDOMAINNAME,
/* [__NR_ia32_newuname - SYSCALL_TABLE_ID0] = PPM_SC_NR_NEWUNAME, */
	[__NR_ia32_adjtimex - SYSCALL_TABLE_ID0] = PPM_SC_ADJTIMEX,
	[__NR_ia32_mprotect - SYSCALL_TABLE_ID0] = PPM_SC_MPROTECT,
	[__NR_ia32_init_module - SYSCALL_TABLE_ID0] = PPM_SC_INIT_MODULE,
	[__NR_ia32_delete_module - SYSCALL_TABLE_ID0] = PPM_SC_DELETE_MODULE,
	[__NR_ia32_quotactl - SYSCALL_TABLE_ID0] = PPM_SC_QUOTACTL,
	[__NR_ia32_getpgid - SYSCALL_TABLE_ID0] = PPM_SC_GETPGID,
	[__NR_ia32_fchdir - SYSCALL_TABLE_ID0] = PPM_SC_FCHDIR,
	[__NR_ia32_sysfs - SYSCALL_TABLE_ID0] = PPM_SC_SYSFS,
	[__NR_ia32_personality - SYSCALL_TABLE_ID0] = PPM_SC_PERSONALITY,
/* [__NR_ia32_setfsuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETFSUID16, */
/* [__NR_ia32_setfsgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETFSGID16, */
/* [__NR_ia32_llseek - SYSCALL_TABLE_ID0] = PPM_SC_NR_LLSEEK, */
	[__NR_ia32_getdents - SYSCALL_TABLE_ID0] = PPM_SC_GETDENTS,
#ifdef __NR_ia32_select
	[__NR_ia32_select - SYSCALL_TABLE_ID0] = PPM_SC_SELECT,
#endif
	[__NR_ia32_flock - SYSCALL_TABLE_ID0] = PPM_SC_FLOCK,
	[__NR_ia32_msync - SYSCALL_TABLE_ID0] = PPM_SC_MSYNC,
	[__NR_ia32_readv - SYSCALL_TABLE_ID0] = PPM_SC_READV,
	[__NR_ia32_writev - SYSCALL_TABLE_ID0] = PPM_SC_WRITEV,
	[__NR_ia32_getsid - SYSCALL_TABLE_ID0] = PPM_SC_GETSID,
	[__NR_ia32_fdatasync - SYSCALL_TABLE_ID0] = PPM_SC_FDATASYNC,
/* [__NR_ia32_sysctl - SYSCALL_TABLE_ID0] = PPM_SC_NR_SYSCTL, */
	[__NR_ia32_mlock - SYSCALL_TABLE_ID0] = PPM_SC_MLOCK,
	[__NR_ia32_munlock - SYSCALL_TABLE_ID0] = PPM_SC_MUNLOCK,
	[__NR_ia32_mlockall - SYSCALL_TABLE_ID0] = PPM_SC_MLOCKALL,
	[__NR_ia32_munlockall - SYSCALL_TABLE_ID0] = PPM_SC_MUNLOCKALL,
	[__NR_ia32_sched_setparam - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_SETPARAM,
	[__NR_ia32_sched_getparam - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GETPARAM,
	[__NR_ia32_sched_setscheduler - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_SETSCHEDULER,
	[__NR_ia32_sched_getscheduler - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GETSCHEDULER,
	[__NR_ia32_sched_yield - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_YIELD,
	[__NR_ia32_sched_get_priority_max - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GET_PRIORITY_MAX,
	[__NR_ia32_sched_get_priority_min - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GET_PRIORITY_MIN,
	[__NR_ia32_sched_rr_get_interval - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_RR_GET_INTERVAL,
	[__NR_ia32_nanosleep - SYSCALL_TABLE_ID0] = PPM_SC_NANOSLEEP,
	[__NR_ia32_mremap - SYSCALL_TABLE_ID0] = PPM_SC_MREMAP,
/* [__NR_ia32_setresuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETRESUID16, */
/* [__NR_ia32_getresuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETRESUID16, */
	[__NR_ia32_poll - SYSCALL_TABLE_ID0] = PPM_SC_POLL,
/* [__NR_ia32_setresgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETRESGID16, */
/* [__NR_ia32_getresgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETRESGID16, */
	[__NR_ia32_prctl - SYSCALL_TABLE_ID0] = PPM_SC_PRCTL,
#ifdef __NR_ia32_arch_prctl
	[__NR_ia32_arch_prctl - SYSCALL_TABLE_ID0] = PPM_SC_ARCH_PRCTL,
#endif
	[__NR_ia32_rt_sigaction - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGACTION,
	[__NR_ia32_rt_sigprocmask - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGPROCMASK,
	[__NR_ia32_rt_sigpending - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGPENDING,
	[__NR_ia32_rt_sigtimedwait - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGTIMEDWAIT,
	[__NR_ia32_rt_sigqueueinfo - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGQUEUEINFO,
	[__NR_ia32_rt_sigsuspend - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGSUSPEND,
/* [__NR_ia32_chown16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_CHOWN16, */
	[__NR_ia32_getcwd - SYSCALL_TABLE_ID0] = PPM_SC_GETCWD,
	[__NR_ia32_capget - SYSCALL_TABLE_ID0] = PPM_SC_CAPGET,
	[__NR_ia32_capset - SYSCALL_TABLE_ID0] = PPM_SC_CAPSET,
	[__NR_ia32_sendfile - SYSCALL_TABLE_ID0] = PPM_SC_SENDFILE,
	[__NR_ia32_getrlimit - SYSCALL_TABLE_ID0] = PPM_SC_GETRLIMIT,
/* [__NR_ia32_mmap_pgoff - SYSCALL_TABLE_ID0] = PPM_SC_NR_MMAP_PGOFF, */
	[__NR_ia32_lchown - SYSCALL_TABLE_ID0] = PPM_SC_LCHOWN,
	[__NR_ia32_getuid - SYSCALL_TABLE_ID0] = PPM_SC_GETUID,
	[__NR_ia32_getgid - SYSCALL_TABLE_ID0] = PPM_SC_GETGID,
	[__NR_ia32_geteuid - SYSCALL_TABLE_ID0] = PPM_SC_GETEUID,
	[__NR_ia32_getegid - SYSCALL_TABLE_ID0] = PPM_SC_GETEGID,
	[__NR_ia32_setreuid - SYSCALL_TABLE_ID0] = PPM_SC_SETREUID,
	[__NR_ia32_setregid - SYSCALL_TABLE_ID0] = PPM_SC_SETREGID,
	[__NR_ia32_getgroups - SYSCALL_TABLE_ID0] = PPM_SC_GETGROUPS,
	[__NR_ia32_setgroups - SYSCALL_TABLE_ID0] = PPM_SC_SETGROUPS,
	[__NR_ia32_fchown - SYSCALL_TABLE_ID0] = PPM_SC_FCHOWN,
	[__NR_ia32_setresuid - SYSCALL_TABLE_ID0] = PPM_SC_SETRESUID,
	[__NR_ia32_getresuid - SYSCALL_TABLE_ID0] = PPM_SC_GETRESUID,
	[__NR_ia32_setresgid - SYSCALL_TABLE_ID0] = PPM_SC_SETRESGID,
	[__NR_ia32_getresgid - SYSCALL_TABLE_ID0] = PPM_SC_GETRESGID,
	[__NR_ia32_chown - SYSCALL_TABLE_ID0] = PPM_SC_CHOWN,
	[__NR_ia32_setuid - SYSCALL_TABLE_ID0] = PPM_SC_SETUID,
	[__NR_ia32_setgid - SYSCALL_TABLE_ID0] = PPM_SC_SETGID,
	[__NR_ia32_setfsuid - SYSCALL_TABLE_ID0] = PPM_SC_SETFSUID,
	[__NR_ia32_setfsgid - SYSCALL_TABLE_ID0] = PPM_SC_SETFSGID,
	[__NR_ia32_pivot_root - SYSCALL_TABLE_ID0] = PPM_SC_PIVOT_ROOT,
	[__NR_ia32_mincore - SYSCALL_TABLE_ID0] = PPM_SC_MINCORE,
	[__NR_ia32_madvise - SYSCALL_TABLE_ID0] = PPM_SC_MADVISE,
	[__NR_ia32_gettid - SYSCALL_TABLE_ID0] = PPM_SC_GETTID,
	[__NR_ia32_setxattr - SYSCALL_TABLE_ID0] = PPM_SC_SETXATTR,
	[__NR_ia32_lsetxattr - SYSCALL_TABLE_ID0] = PPM_SC_LSETXATTR,
	[__NR_ia32_fsetxattr - SYSCALL_TABLE_ID0] = PPM_SC_FSETXATTR,
	[__NR_ia32_getxattr - SYSCALL_TABLE_ID0] = PPM_SC_GETXATTR,
	[__NR_ia32_lgetxattr - SYSCALL_TABLE_ID0] = PPM_SC_LGETXATTR,
	[__NR_ia32_fgetxattr - SYSCALL_TABLE_ID0] = PPM_SC_FGETXATTR,
	[__NR_ia32_listxattr - SYSCALL_TABLE_ID0] = PPM_SC_LISTXATTR,
	[__NR_ia32_llistxattr - SYSCALL_TABLE_ID0] = PPM_SC_LLISTXATTR,
	[__NR_ia32_flistxattr - SYSCALL_TABLE_ID0] = PPM_SC_FLISTXATTR,
	[__NR_ia32_removexattr - SYSCALL_TABLE_ID0] = PPM_SC_REMOVEXATTR,
	[__NR_ia32_lremovexattr - SYSCALL_TABLE_ID0] = PPM_SC_LREMOVEXATTR,
	[__NR_ia32_fremovexattr - SYSCALL_TABLE_ID0] = PPM_SC_FREMOVEXATTR,
	[__NR_ia32_tkill - SYSCALL_TABLE_ID0] = PPM_SC_TKILL,
	[__NR_ia32_futex - SYSCALL_TABLE_ID0] = PPM_SC_FUTEX,
	[__NR_ia32_sched_setaffinity - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_SETAFFINITY,
	[__NR_ia32_sched_getaffinity - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GETAFFINITY,
#ifdef __NR_ia32_set_thread_area
	[__NR_ia32_set_thread_area - SYSCALL_TABLE_ID0] = PPM_SC_SET_THREAD_AREA,
#endif
#ifdef __NR_ia32_get_thread_area
	[__NR_ia32_get_thread_area - SYSCALL_TABLE_ID0] = PPM_SC_GET_THREAD_AREA,
#endif
	[__NR_ia32_io_setup - SYSCALL_TABLE_ID0] = PPM_SC_IO_SETUP,
	[__NR_ia32_io_destroy - SYSCALL_TABLE_ID0] = PPM_SC_IO_DESTROY,
	[__NR_ia32_io_getevents - SYSCALL_TABLE_ID0] = PPM_SC_IO_GETEVENTS,
	[__NR_ia32_io_submit - SYSCALL_TABLE_ID0] = PPM_SC_IO_SUBMIT,
	[__NR_ia32_io_cancel - SYSCALL_TABLE_ID0] = PPM_SC_IO_CANCEL,
	[__NR_ia32_exit_group - SYSCALL_TABLE_ID0] = PPM_SC_EXIT_GROUP,
	[__NR_ia32_epoll_create - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_CREATE,
	[__NR_ia32_epoll_ctl - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_CTL,
	[__NR_ia32_epoll_wait - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_WAIT,
	[__NR_ia32_remap_file_pages - SYSCALL_TABLE_ID0] = PPM_SC_REMAP_FILE_PAGES,
	[__NR_ia32_set_tid_address - SYSCALL_TABLE_ID0] = PPM_SC_SET_TID_ADDRESS,
	[__NR_ia32_timer_create - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_CREATE,
	[__NR_ia32_timer_settime - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_SETTIME,
	[__NR_ia32_timer_gettime - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_GETTIME,
	[__NR_ia32_timer_getoverrun - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_GETOVERRUN,
	[__NR_ia32_timer_delete - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_DELETE,
	[__NR_ia32_clock_settime - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_SETTIME,
	[__NR_ia32_clock_gettime - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_GETTIME,
	[__NR_ia32_clock_getres - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_GETRES,
	[__NR_ia32_clock_nanosleep - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_NANOSLEEP,
	[__NR_ia32_tgkill - SYSCALL_TABLE_ID0] = PPM_SC_TGKILL,
	[__NR_ia32_utimes - SYSCALL_TABLE_ID0] = PPM_SC_UTIMES,
	[__NR_ia32_mq_open - SYSCALL_TABLE_ID0] = PPM_SC_MQ_OPEN,
	[__NR_ia32_mq_unlink - SYSCALL_TABLE_ID0] = PPM_SC_MQ_UNLINK,
	[__NR_ia32_mq_timedsend - SYSCALL_TABLE_ID0] = PPM_SC_MQ_TIMEDSEND,
	[__NR_ia32_mq_timedreceive - SYSCALL_TABLE_ID0] = PPM_SC_MQ_TIMEDRECEIVE,
	[__NR_ia32_mq_notify - SYSCALL_TABLE_ID0] = PPM_SC_MQ_NOTIFY,
	[__NR_ia32_mq_getsetattr - SYSCALL_TABLE_ID0] = PPM_SC_MQ_GETSETATTR,
	[__NR_ia32_kexec_load - SYSCALL_TABLE_ID0] = PPM_SC_KEXEC_LOAD,
	[__NR_ia32_waitid - SYSCALL_TABLE_ID0] = PPM_SC_WAITID,
	[__NR_ia32_add_key - SYSCALL_TABLE_ID0] = PPM_SC_ADD_KEY,
	[__NR_ia32_request_key - SYSCALL_TABLE_ID0] = PPM_SC_REQUEST_KEY,
	[__NR_ia32_keyctl - SYSCALL_TABLE_ID0] = PPM_SC_KEYCTL,
	[__NR_ia32_ioprio_set - SYSCALL_TABLE_ID0] = PPM_SC_IOPRIO_SET,
	[__NR_ia32_ioprio_get - SYSCALL_TABLE_ID0] = PPM_SC_IOPRIO_GET,
	[__NR_ia32_inotify_init - SYSCALL_TABLE_ID0] = PPM_SC_INOTIFY_INIT,
	[__NR_ia32_inotify_add_watch - SYSCALL_TABLE_ID0] = PPM_SC_INOTIFY_ADD_WATCH,
	[__NR_ia32_inotify_rm_watch - SYSCALL_TABLE_ID0] = PPM_SC_INOTIFY_RM_WATCH,
	[__NR_ia32_openat - SYSCALL_TABLE_ID0] = PPM_SC_OPENAT,
	[__NR_ia32_mkdirat - SYSCALL_TABLE_ID0] = PPM_SC_MKDIRAT,
	[__NR_ia32_mknodat - SYSCALL_TABLE_ID0] = PPM_SC_MKNODAT,
	[__NR_ia32_fchownat - SYSCALL_TABLE_ID0] = PPM_SC_FCHOWNAT,
	[__NR_ia32_futimesat - SYSCALL_TABLE_ID0] = PPM_SC_FUTIMESAT,
	[__NR_ia32_unlinkat - SYSCALL_TABLE_ID0] = PPM_SC_UNLINKAT,
	[__NR_ia32_renameat - SYSCALL_TABLE_ID0] = PPM_SC_RENAMEAT,
	[__NR_ia32_linkat - SYSCALL_TABLE_ID0] = PPM_SC_LINKAT,
	[__NR_ia32_symlinkat - SYSCALL_TABLE_ID0] = PPM_SC_SYMLINKAT,
	[__NR_ia32_readlinkat - SYSCALL_TABLE_ID0] = PPM_SC_READLINKAT,
	[__NR_ia32_fchmodat - SYSCALL_TABLE_ID0] = PPM_SC_FCHMODAT,
	[__NR_ia32_faccessat - SYSCALL_TABLE_ID0] = PPM_SC_FACCESSAT,
	[__NR_ia32_pselect6 - SYSCALL_TABLE_ID0] = PPM_SC_PSELECT6,
	[__NR_ia32_ppoll - SYSCALL_TABLE_ID0] = PPM_SC_PPOLL,
	[__NR_ia32_unshare - SYSCALL_TABLE_ID0] = PPM_SC_UNSHARE,
	[__NR_ia32_set_robust_list - SYSCALL_TABLE_ID0] = PPM_SC_SET_ROBUST_LIST,
	[__NR_ia32_get_robust_list - SYSCALL_TABLE_ID0] = PPM_SC_GET_ROBUST_LIST,
	[__NR_ia32_splice - SYSCALL_TABLE_ID0] = PPM_SC_SPLICE,
	[__NR_ia32_tee - SYSCALL_TABLE_ID0] = PPM_SC_TEE,
	[__NR_ia32_vmsplice - SYSCALL_TABLE_ID0] = PPM_SC_VMSPLICE,
#ifdef __NR_ia32_getcpu
	[__NR_ia32_getcpu - SYSCALL_TABLE_ID0] = PPM_SC_GETCPU,
#endif
	[__NR_ia32_epoll_pwait - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_PWAIT,
	[__NR_ia32_utimensat - SYSCALL_TABLE_ID0] = PPM_SC_UTIMENSAT,
	[__NR_ia32_signalfd - SYSCALL_TABLE_ID0] = PPM_SC_SIGNALFD,
	[__NR_ia32_timerfd_create - SYSCALL_TABLE_ID0] = PPM_SC_TIMERFD_CREATE,
	[__NR_ia32_eventfd - SYSCALL_TABLE_ID0] = PPM_SC_EVENTFD,
	[__NR_ia32_timerfd_settime - SYSCALL_TABLE_ID0] = PPM_SC_TIMERFD_SETTIME,
	[__NR_ia32_timerfd_gettime - SYSCALL_TABLE_ID0] = PPM_SC_TIMERFD_GETTIME,
	[__NR_ia32_signalfd4 - SYSCALL_TABLE_ID0] = PPM_SC_SIGNALFD4,
	[__NR_ia32_eventfd2 - SYSCALL_TABLE_ID0] = PPM_SC_EVENTFD2,
	[__NR_ia32_epoll_create1 - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_CREATE1,
	[__NR_ia32_dup3 - SYSCALL_TABLE_ID0] = PPM_SC_DUP3,
	[__NR_ia32_pipe2 - SYSCALL_TABLE_ID0] = PPM_SC_PIPE2,
	[__NR_ia32_inotify_init1 - SYSCALL_TABLE_ID0] = PPM_SC_INOTIFY_INIT1,
	[__NR_ia32_preadv - SYSCALL_TABLE_ID0] = PPM_SC_PREADV,
	[__NR_ia32_pwritev - SYSCALL_TABLE_ID0] = PPM_SC_PWRITEV,
	[__NR_ia32_rt_tgsigqueueinfo - SYSCALL_TABLE_ID0] = PPM_SC_RT_TGSIGQUEUEINFO,
	[__NR_ia32_perf_event_open - SYSCALL_TABLE_ID0] = PPM_SC_PERF_EVENT_OPEN,
#ifdef __NR_ia32_fanotify_init
	[__NR_ia32_fanotify_init - SYSCALL_TABLE_ID0] = PPM_SC_FANOTIFY_INIT,
#endif
#ifdef __NR_ia32_prlimit64
	[__NR_ia32_prlimit64 - SYSCALL_TABLE_ID0] = PPM_SC_PRLIMIT64,
#endif
#ifdef __NR_ia32_clock_adjtime
	[__NR_ia32_clock_adjtime - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_ADJTIME,
#endif
#ifdef __NR_ia32_syncfs
	[__NR_ia32_syncfs - SYSCALL_TABLE_ID0] = PPM_SC_SYNCFS,
#endif
#ifdef __NR_ia32_setns
	[__NR_ia32_setns - SYSCALL_TABLE_ID0] = PPM_SC_SETNS,
#endif
	[__NR_ia32_getdents64 - SYSCALL_TABLE_ID0] =  PPM_SC_GETDENTS64,
#ifndef __NR_ia32_socketcall
	/*
	 * Non-multiplexed socket family
	 */
	[__NR_ia32_socket - SYSCALL_TABLE_ID0] =  PPM_SC_SOCKET,
	[__NR_ia32_bind - SYSCALL_TABLE_ID0] =	PPM_SC_BIND,
	[__NR_ia32_connect - SYSCALL_TABLE_ID0] =  PPM_SC_CONNECT,
	[__NR_ia32_listen - SYSCALL_TABLE_ID0] =  PPM_SC_LISTEN,
	[__NR_ia32_accept - SYSCALL_TABLE_ID0] =  PPM_SC_ACCEPT,
	[__NR_ia32_getsockname - SYSCALL_TABLE_ID0] = PPM_SC_GETSOCKNAME,
	[__NR_ia32_getpeername - SYSCALL_TABLE_ID0] = PPM_SC_GETPEERNAME,
	[__NR_ia32_socketpair - SYSCALL_TABLE_ID0] = PPM_SC_SOCKETPAIR,
/* [__NR_ia32_send - SYSCALL_TABLE_ID0] =	PPM_SC_NR_SEND, */
	[__NR_ia32_sendto - SYSCALL_TABLE_ID0] =  PPM_SC_SENDTO,
/* [__NR_ia32_recv - SYSCALL_TABLE_ID0] =	PPM_SC_NR_RECV, */
	[__NR_ia32_recvfrom - SYSCALL_TABLE_ID0] =  PPM_SC_RECVFROM,
	[__NR_ia32_shutdown - SYSCALL_TABLE_ID0] =  PPM_SC_SHUTDOWN,
	[__NR_ia32_setsockopt - SYSCALL_TABLE_ID0] = PPM_SC_SETSOCKOPT,
	[__NR_ia32_getsockopt - SYSCALL_TABLE_ID0] = PPM_SC_GETSOCKOPT,
	[__NR_ia32_sendmsg - SYSCALL_TABLE_ID0] =  PPM_SC_SENDMSG,
	[__NR_ia32_recvmsg - SYSCALL_TABLE_ID0] =  PPM_SC_RECVMSG,
	[__NR_ia32_accept4 - SYSCALL_TABLE_ID0] =  PPM_SC_ACCEPT4,
#else
	[__NR_ia32_socketcall - SYSCALL_TABLE_ID0] = PPM_SC_SOCKETCALL,
#endif


#ifdef __NR_ia32_sendmmsg
	[__NR_ia32_sendmmsg - SYSCALL_TABLE_ID0] =  PPM_SC_SENDMMSG,
#endif
#ifdef __NR_ia32_recvmmsg
	[__NR_ia32_recvmmsg - SYSCALL_TABLE_ID0] =  PPM_SC_RECVMMSG,
#endif
	/*
	 * Non-multiplexed IPC family
	 */
#ifdef __NR_ia32_semop
	[__NR_ia32_semop - SYSCALL_TABLE_ID0] =  PPM_SC_SEMOP,
#endif
#ifdef __NR_ia32_semget
	[__NR_ia32_semget - SYSCALL_TABLE_ID0] =  PPM_SC_SEMGET,
#endif
#ifdef __NR_ia32_semctl
	[__NR_ia32_semctl - SYSCALL_TABLE_ID0] =  PPM_SC_SEMCTL,
#endif
#ifdef __NR_ia32_semget
	[__NR_ia32_semget - SYSCALL_TABLE_ID0] =  PPM_SC_SEMGET,
#endif
#ifdef __NR_ia32_msgsnd
	[__NR_ia32_msgsnd - SYSCALL_TABLE_ID0] =  PPM_SC_MSGSND,
#endif
#ifdef __NR_ia32_msgrcv
	[__NR_ia32_msgrcv - SYSCALL_TABLE_ID0] =  PPM_SC_MSGRCV,
#endif
#ifdef __NR_ia32_msgget
	[__NR_ia32_msgget - SYSCALL_TABLE_ID0] =  PPM_SC_MSGGET,
#endif
#ifdef __NR_ia32_msgctl
	[__NR_ia32_msgctl - SYSCALL_TABLE_ID0] =  PPM_SC_MSGCTL,
#endif
/* [__NR_ia32_shmatcall - SYSCALL_TABLE_ID0] =  PPM_SC_NR_SHMATCALL, */
#ifdef __NR_ia32_shmdt
	[__NR_ia32_shmdt - SYSCALL_TABLE_ID0] =  PPM_SC_SHMDT,
#endif
#ifdef __NR_ia32_shmget
	[__NR_ia32_shmget - SYSCALL_TABLE_ID0] =  PPM_SC_SHMGET,
#endif
#ifdef __NR_ia32_shmctl
	[__NR_ia32_shmctl - SYSCALL_TABLE_ID0] =  PPM_SC_SHMCTL,
#endif
/* [__NR_ia32_fcntl64 - SYSCALL_TABLE_ID0] =  PPM_SC_NR_FCNTL64, */
#ifdef __NR_ia32_statfs64
	[__NR_ia32_statfs64 - SYSCALL_TABLE_ID0] = PPM_SC_STATFS64,
#endif
#ifdef __NR_ia32_fstatfs64
	[__NR_ia32_fstatfs64 - SYSCALL_TABLE_ID0] = PPM_SC_FSTATFS64,
#endif
#ifdef __NR_ia32_fstatat64
	[__NR_ia32_fstatat64 - SYSCALL_TABLE_ID0] = PPM_SC_FSTATAT64,
#endif
#ifdef __NR_ia32_sendfile64
	[__NR_ia32_sendfile64 - SYSCALL_TABLE_ID0] = PPM_SC_SENDFILE64,
#endif
#ifdef __NR_ia32_ugetrlimit
	[__NR_ia32_ugetrlimit - SYSCALL_TABLE_ID0] = PPM_SC_UGETRLIMIT,
#endif
#ifdef __NR_ia32_bdflush
	[__NR_ia32_bdflush - SYSCALL_TABLE_ID0] = PPM_SC_BDFLUSH,
#endif
#ifdef __NR_ia32_sigprocmask
	[__NR_ia32_sigprocmask - SYSCALL_TABLE_ID0] = PPM_SC_SIGPROCMASK,
#endif
#ifdef __NR_ia32_ipc
	[__NR_ia32_ipc - SYSCALL_TABLE_ID0] = PPM_SC_IPC,
#endif
#ifdef __NR_ia32_stat64
	[__NR_ia32_stat64 - SYSCALL_TABLE_ID0] = PPM_SC_STAT64,
#endif
#ifdef __NR_ia32_lstat64
	[__NR_ia32_lstat64 - SYSCALL_TABLE_ID0] = PPM_SC_LSTAT64,
#endif
#ifdef __NR_ia32_fstat64
	[__NR_ia32_fstat64 - SYSCALL_TABLE_ID0] = PPM_SC_FSTAT64,
#endif
#ifdef __NR_ia32_fcntl64
	[__NR_ia32_fcntl64 - SYSCALL_TABLE_ID0] = PPM_SC_FCNTL64,
#endif
#ifdef __NR_ia32_mmap2
	[__NR_ia32_mmap2 - SYSCALL_TABLE_ID0] = PPM_SC_MMAP2,
#endif
#ifdef __NR_ia32__newselect
	[__NR_ia32__newselect - SYSCALL_TABLE_ID0] = PPM_SC__NEWSELECT,
#endif
#ifdef __NR_ia32_sgetmask
	[__NR_ia32_sgetmask - SYSCALL_TABLE_ID0] = PPM_SC_SGETMASK,
#endif
#ifdef __NR_ia32_ssetmask
	[__NR_ia32_ssetmask - SYSCALL_TABLE_ID0] = PPM_SC_SSETMASK,
#endif

/* [__NR_ia32_setreuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETREUID16, */
/* [__NR_ia32_setregid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETREGID16, */
#ifdef __NR_ia32_sigpending
	[__NR_ia32_sigpending - SYSCALL_TABLE_ID0] = PPM_SC_SIGPENDING,
#endif
#ifdef __NR_ia32_olduname
	[__NR_ia32_olduname - SYSCALL_TABLE_ID0] = PPM_SC_OLDUNAME,
#endif
#ifdef __NR_ia32_umount
	[__NR_ia32_umount - SYSCALL_TABLE_ID0] = PPM_SC_UMOUNT,
#endif
#ifdef __NR_ia32_signal
	[__NR_ia32_signal - SYSCALL_TABLE_ID0] = PPM_SC_SIGNAL,
#endif
#ifdef __NR_ia32_nice
	[__NR_ia32_nice - SYSCALL_TABLE_ID0] = PPM_SC_NICE,
#endif
#ifdef __NR_ia32_stime
	[__NR_ia32_stime - SYSCALL_TABLE_ID0] = PPM_SC_STIME,
#endif
#ifdef __NR_ia32__llseek
	[__NR_ia32__llseek - SYSCALL_TABLE_ID0] = PPM_SC__LLSEEK,
#endif
#ifdef __NR_ia32_waitpid
	[__NR_ia32_waitpid - SYSCALL_TABLE_ID0] = PPM_SC_WAITPID,
#endif
#ifdef __NR_ia32_pread64
	[__NR_ia32_pread64 - SYSCALL_TABLE_ID0] = PPM_SC_PREAD64,
#endif
#ifdef __NR_ia32_pwrite64
	[__NR_ia32_pwrite64 - SYSCALL_TABLE_ID0] = PPM_SC_PWRITE64,
#endif
#ifdef __NR_ia32_shmat
	[__NR_ia32_shmat - SYSCALL_TABLE_ID0] = PPM_SC_SHMAT,
#endif
#ifdef __NR_ia32_rt_sigreturn
	[__NR_ia32_rt_sigreturn - SYSCALL_TABLE_ID0] = PPM_SC_SIGRETURN,
#endif
#ifdef __NR_ia32_fallocate
	[__NR_ia32_fallocate - SYSCALL_TABLE_ID0] = PPM_SC_FALLOCATE,
#endif
#ifdef __NR_ia32_newfstatat
	[__NR_ia32_newfstatat - SYSCALL_TABLE_ID0] = PPM_SC_NEWFSSTAT,
#endif
#ifdef __NR_ia32_process_vm_readv
	[__NR_ia32_process_vm_readv - SYSCALL_TABLE_ID0] = PPM_SC_PROCESS_VM_READV,
#endif
#ifdef __NR_ia32_process_vm_writev
	[__NR_ia32_process_vm_writev - SYSCALL_TABLE_ID0] = PPM_SC_PROCESS_VM_WRITEV,
#endif
#ifdef __NR_ia32_fork
	[__NR_ia32_fork - SYSCALL_TABLE_ID0] = PPM_SC_FORK,
#endif
#ifdef __NR_ia32_vfork
	[__NR_ia32_vfork - SYSCALL_TABLE_ID0] = PPM_SC_VFORK,
#endif
#ifdef __NR_ia32_quotactl
	[__NR_ia32_quotactl - SYSCALL_TABLE_ID0] = PPM_SC_QUOTACTL,
#endif
#ifdef __NR_ia32_setresuid
	[__NR_ia32_setresuid - SYSCALL_TABLE_ID0] = PPM_SC_SETRESUID,
#endif
#ifdef __NR_ia32_setresuid32
	[__NR_ia32_setresuid32 - SYSCALL_TABLE_ID0] = PPM_SC_SETRESUID,
#endif
#ifdef __NR_ia32_setresgid
	[__NR_ia32_setresgid - SYSCALL_TABLE_ID0] = PPM_SC_SETRESGID,
#endif
#ifdef __NR_ia32_setresgid32
	[__NR_ia32_setresgid32 - SYSCALL_TABLE_ID0] = PPM_SC_SETRESGID,
#endif
#ifdef __NR_ia32_setuid
	[__NR_ia32_setuid - SYSCALL_TABLE_ID0] = PPM_SC_SETUID,
#endif
#ifdef __NR_ia32_setuid32
	[__NR_ia32_setuid32 - SYSCALL_TABLE_ID0] = PPM_SC_SETUID32,
#endif
#ifdef __NR_ia32_setgid
	[__NR_ia32_setgid - SYSCALL_TABLE_ID0] = PPM_SC_SETGID,
#endif
#ifdef __NR_ia32_setgid32
	[__NR_ia32_setgid32 - SYSCALL_TABLE_ID0] = PPM_SC_SETGID32,
#endif
#ifdef __NR_ia32_getuid
	[__NR_ia32_getuid - SYSCALL_TABLE_ID0] = PPM_SC_GETUID,
#endif
#ifdef __NR_ia32_getuid32
	[__NR_ia32_getuid32 - SYSCALL_TABLE_ID0] = PPM_SC_GETUID32,
#endif
#ifdef __NR_ia32_geteuid
	[__NR_ia32_geteuid - SYSCALL_TABLE_ID0] = PPM_SC_GETEUID,
#endif
#ifdef __NR_ia32_geteuid32
	[__NR_ia32_geteuid32 - SYSCALL_TABLE_ID0] = PPM_SC_GETEUID,
#endif
#ifdef __NR_ia32_getgid
	[__NR_ia32_getgid - SYSCALL_TABLE_ID0] = PPM_SC_GETGID,
#endif
#ifdef __NR_ia32_getgid32
	[__NR_ia32_getgid32 - SYSCALL_TABLE_ID0] = PPM_SC_GETGID,
#endif
#ifdef __NR_ia32_getegid
	[__NR_ia32_getegid - SYSCALL_TABLE_ID0] = PPM_SC_GETEGID,
#endif
#ifdef __NR_ia32_getegid32
	[__NR_ia32_getegid32 - SYSCALL_TABLE_ID0] = PPM_SC_GETEGID,
#endif
#ifdef __NR_ia32_getresuid
	[__NR_ia32_getresuid - SYSCALL_TABLE_ID0] = PPM_SC_GETRESUID,
#endif
#ifdef __NR_ia32_getresuid32
	[__NR_ia32_getresuid32 - SYSCALL_TABLE_ID0] = PPM_SC_GETRESUID32,
#endif
#ifdef __NR_ia32_getresgid
	[__NR_ia32_getresgid - SYSCALL_TABLE_ID0] = PPM_SC_GETRESGID,
#endif
#ifdef __NR_ia32_getresgid32
	[__NR_ia32_getresgid32 - SYSCALL_TABLE_ID0] = PPM_SC_GETRESGID32,
#endif
#ifdef __NR_ia32_finit_module
	[__NR_ia32_finit_module - SYSCALL_TABLE_ID0] = PPM_SC_FINIT_MODULE,
#endif
#ifdef __NR_ia32_bpf
	[__NR_ia32_bpf - SYSCALL_TABLE_ID0] = PPM_SC_BPF,
#endif
#ifdef __NR_ia32_seccomp
	[__NR_ia32_seccomp - SYSCALL_TABLE_ID0] = PPM_SC_SECCOMP,
#endif
#ifdef __NR_ia32_sigaltstack
	[__NR_ia32_sigaltstack - SYSCALL_TABLE_ID0] = PPM_SC_SIGALTSTACK,
#endif
#ifdef __NR_ia32_getrandom
	[__NR_ia32_getrandom - SYSCALL_TABLE_ID0] = PPM_SC_GETRANDOM,
#endif
#ifdef __NR_ia32_fadvise64
	[__NR_ia32_fadvise64 - SYSCALL_TABLE_ID0] = PPM_SC_FADVISE64,
#endif
};

#endif /* CONFIG_IA32_EMULATION */
