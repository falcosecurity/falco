#pragma once
#ifndef __NR_read
#define __NR_read 0
#endif
#ifndef __NR_write
#define __NR_write 1
#endif
#ifndef __NR_open
#define __NR_open 2
#endif
#ifndef __NR_close
#define __NR_close 3
#endif
#ifndef __NR_stat
#define __NR_stat 4
#endif
#ifndef __NR_fstat
#define __NR_fstat 5
#endif
#ifndef __NR_lstat
#define __NR_lstat 6
#endif
#ifndef __NR_poll
#define __NR_poll 7
#endif
#ifndef __NR_lseek
#define __NR_lseek 8
#endif
#ifndef __NR_mmap
#define __NR_mmap 9
#endif
#ifndef __NR_mprotect
#define __NR_mprotect 10
#endif
#ifndef __NR_munmap
#define __NR_munmap 11
#endif
#ifndef __NR_brk
#define __NR_brk 12
#endif
#ifndef __NR_rt_sigaction
#define __NR_rt_sigaction 13
#endif
#ifndef __NR_rt_sigprocmask
#define __NR_rt_sigprocmask 14
#endif
#ifndef __NR_rt_sigreturn
#define __NR_rt_sigreturn 15
#endif
#ifndef __NR_ioctl
#define __NR_ioctl 16
#endif
#ifndef __NR_pread64
#define __NR_pread64 17
#endif
#ifndef __NR_pwrite64
#define __NR_pwrite64 18
#endif
#ifndef __NR_readv
#define __NR_readv 19
#endif
#ifndef __NR_writev
#define __NR_writev 20
#endif
#ifndef __NR_access
#define __NR_access 21
#endif
#ifndef __NR_pipe
#define __NR_pipe 22
#endif
#ifndef __NR_select
#define __NR_select 23
#endif
#ifndef __NR_sched_yield
#define __NR_sched_yield 24
#endif
#ifndef __NR_mremap
#define __NR_mremap 25
#endif
#ifndef __NR_msync
#define __NR_msync 26
#endif
#ifndef __NR_mincore
#define __NR_mincore 27
#endif
#ifndef __NR_madvise
#define __NR_madvise 28
#endif
#ifndef __NR_shmget
#define __NR_shmget 29
#endif
#ifndef __NR_shmat
#define __NR_shmat 30
#endif
#ifndef __NR_shmctl
#define __NR_shmctl 31
#endif
#ifndef __NR_dup
#define __NR_dup 32
#endif
#ifndef __NR_dup2
#define __NR_dup2 33
#endif
#ifndef __NR_pause
#define __NR_pause 34
#endif
#ifndef __NR_nanosleep
#define __NR_nanosleep 35
#endif
#ifndef __NR_getitimer
#define __NR_getitimer 36
#endif
#ifndef __NR_alarm
#define __NR_alarm 37
#endif
#ifndef __NR_setitimer
#define __NR_setitimer 38
#endif
#ifndef __NR_getpid
#define __NR_getpid 39
#endif
#ifndef __NR_sendfile
#define __NR_sendfile 40
#endif
#ifndef __NR_socket
#define __NR_socket 41
#endif
#ifndef __NR_connect
#define __NR_connect 42
#endif
#ifndef __NR_accept
#define __NR_accept 43
#endif
#ifndef __NR_sendto
#define __NR_sendto 44
#endif
#ifndef __NR_recvfrom
#define __NR_recvfrom 45
#endif
#ifndef __NR_sendmsg
#define __NR_sendmsg 46
#endif
#ifndef __NR_recvmsg
#define __NR_recvmsg 47
#endif
#ifndef __NR_shutdown
#define __NR_shutdown 48
#endif
#ifndef __NR_bind
#define __NR_bind 49
#endif
#ifndef __NR_listen
#define __NR_listen 50
#endif
#ifndef __NR_getsockname
#define __NR_getsockname 51
#endif
#ifndef __NR_getpeername
#define __NR_getpeername 52
#endif
#ifndef __NR_socketpair
#define __NR_socketpair 53
#endif
#ifndef __NR_setsockopt
#define __NR_setsockopt 54
#endif
#ifndef __NR_getsockopt
#define __NR_getsockopt 55
#endif
#ifndef __NR_clone
#define __NR_clone 56
#endif
#ifndef __NR_fork
#define __NR_fork 57
#endif
#ifndef __NR_vfork
#define __NR_vfork 58
#endif
#ifndef __NR_execve
#define __NR_execve 59
#endif
#ifndef __NR_exit
#define __NR_exit 60
#endif
#ifndef __NR_wait4
#define __NR_wait4 61
#endif
#ifndef __NR_kill
#define __NR_kill 62
#endif
#ifndef __NR_uname
#define __NR_uname 63
#endif
#ifndef __NR_semget
#define __NR_semget 64
#endif
#ifndef __NR_semop
#define __NR_semop 65
#endif
#ifndef __NR_semctl
#define __NR_semctl 66
#endif
#ifndef __NR_shmdt
#define __NR_shmdt 67
#endif
#ifndef __NR_msgget
#define __NR_msgget 68
#endif
#ifndef __NR_msgsnd
#define __NR_msgsnd 69
#endif
#ifndef __NR_msgrcv
#define __NR_msgrcv 70
#endif
#ifndef __NR_msgctl
#define __NR_msgctl 71
#endif
#ifndef __NR_fcntl
#define __NR_fcntl 72
#endif
#ifndef __NR_flock
#define __NR_flock 73
#endif
#ifndef __NR_fsync
#define __NR_fsync 74
#endif
#ifndef __NR_fdatasync
#define __NR_fdatasync 75
#endif
#ifndef __NR_truncate
#define __NR_truncate 76
#endif
#ifndef __NR_ftruncate
#define __NR_ftruncate 77
#endif
#ifndef __NR_getdents
#define __NR_getdents 78
#endif
#ifndef __NR_getcwd
#define __NR_getcwd 79
#endif
#ifndef __NR_chdir
#define __NR_chdir 80
#endif
#ifndef __NR_fchdir
#define __NR_fchdir 81
#endif
#ifndef __NR_rename
#define __NR_rename 82
#endif
#ifndef __NR_mkdir
#define __NR_mkdir 83
#endif
#ifndef __NR_rmdir
#define __NR_rmdir 84
#endif
#ifndef __NR_creat
#define __NR_creat 85
#endif
#ifndef __NR_link
#define __NR_link 86
#endif
#ifndef __NR_unlink
#define __NR_unlink 87
#endif
#ifndef __NR_symlink
#define __NR_symlink 88
#endif
#ifndef __NR_readlink
#define __NR_readlink 89
#endif
#ifndef __NR_chmod
#define __NR_chmod 90
#endif
#ifndef __NR_fchmod
#define __NR_fchmod 91
#endif
#ifndef __NR_chown
#define __NR_chown 92
#endif
#ifndef __NR_fchown
#define __NR_fchown 93
#endif
#ifndef __NR_lchown
#define __NR_lchown 94
#endif
#ifndef __NR_umask
#define __NR_umask 95
#endif
#ifndef __NR_gettimeofday
#define __NR_gettimeofday 96
#endif
#ifndef __NR_getrlimit
#define __NR_getrlimit 97
#endif
#ifndef __NR_getrusage
#define __NR_getrusage 98
#endif
#ifndef __NR_sysinfo
#define __NR_sysinfo 99
#endif
#ifndef __NR_times
#define __NR_times 100
#endif
#ifndef __NR_ptrace
#define __NR_ptrace 101
#endif
#ifndef __NR_getuid
#define __NR_getuid 102
#endif
#ifndef __NR_syslog
#define __NR_syslog 103
#endif
#ifndef __NR_getgid
#define __NR_getgid 104
#endif
#ifndef __NR_setuid
#define __NR_setuid 105
#endif
#ifndef __NR_setgid
#define __NR_setgid 106
#endif
#ifndef __NR_geteuid
#define __NR_geteuid 107
#endif
#ifndef __NR_getegid
#define __NR_getegid 108
#endif
#ifndef __NR_setpgid
#define __NR_setpgid 109
#endif
#ifndef __NR_getppid
#define __NR_getppid 110
#endif
#ifndef __NR_getpgrp
#define __NR_getpgrp 111
#endif
#ifndef __NR_setsid
#define __NR_setsid 112
#endif
#ifndef __NR_setreuid
#define __NR_setreuid 113
#endif
#ifndef __NR_setregid
#define __NR_setregid 114
#endif
#ifndef __NR_getgroups
#define __NR_getgroups 115
#endif
#ifndef __NR_setgroups
#define __NR_setgroups 116
#endif
#ifndef __NR_setresuid
#define __NR_setresuid 117
#endif
#ifndef __NR_getresuid
#define __NR_getresuid 118
#endif
#ifndef __NR_setresgid
#define __NR_setresgid 119
#endif
#ifndef __NR_getresgid
#define __NR_getresgid 120
#endif
#ifndef __NR_getpgid
#define __NR_getpgid 121
#endif
#ifndef __NR_setfsuid
#define __NR_setfsuid 122
#endif
#ifndef __NR_setfsgid
#define __NR_setfsgid 123
#endif
#ifndef __NR_getsid
#define __NR_getsid 124
#endif
#ifndef __NR_capget
#define __NR_capget 125
#endif
#ifndef __NR_capset
#define __NR_capset 126
#endif
#ifndef __NR_rt_sigpending
#define __NR_rt_sigpending 127
#endif
#ifndef __NR_rt_sigtimedwait
#define __NR_rt_sigtimedwait 128
#endif
#ifndef __NR_rt_sigqueueinfo
#define __NR_rt_sigqueueinfo 129
#endif
#ifndef __NR_rt_sigsuspend
#define __NR_rt_sigsuspend 130
#endif
#ifndef __NR_sigaltstack
#define __NR_sigaltstack 131
#endif
#ifndef __NR_utime
#define __NR_utime 132
#endif
#ifndef __NR_mknod
#define __NR_mknod 133
#endif
#ifndef __NR_uselib
#define __NR_uselib 134
#endif
#ifndef __NR_personality
#define __NR_personality 135
#endif
#ifndef __NR_ustat
#define __NR_ustat 136
#endif
#ifndef __NR_statfs
#define __NR_statfs 137
#endif
#ifndef __NR_fstatfs
#define __NR_fstatfs 138
#endif
#ifndef __NR_sysfs
#define __NR_sysfs 139
#endif
#ifndef __NR_getpriority
#define __NR_getpriority 140
#endif
#ifndef __NR_setpriority
#define __NR_setpriority 141
#endif
#ifndef __NR_sched_setparam
#define __NR_sched_setparam 142
#endif
#ifndef __NR_sched_getparam
#define __NR_sched_getparam 143
#endif
#ifndef __NR_sched_setscheduler
#define __NR_sched_setscheduler 144
#endif
#ifndef __NR_sched_getscheduler
#define __NR_sched_getscheduler 145
#endif
#ifndef __NR_sched_get_priority_max
#define __NR_sched_get_priority_max 146
#endif
#ifndef __NR_sched_get_priority_min
#define __NR_sched_get_priority_min 147
#endif
#ifndef __NR_sched_rr_get_interval
#define __NR_sched_rr_get_interval 148
#endif
#ifndef __NR_mlock
#define __NR_mlock 149
#endif
#ifndef __NR_munlock
#define __NR_munlock 150
#endif
#ifndef __NR_mlockall
#define __NR_mlockall 151
#endif
#ifndef __NR_munlockall
#define __NR_munlockall 152
#endif
#ifndef __NR_vhangup
#define __NR_vhangup 153
#endif
#ifndef __NR_modify_ldt
#define __NR_modify_ldt 154
#endif
#ifndef __NR_pivot_root
#define __NR_pivot_root 155
#endif
#ifndef __NR__sysctl
#define __NR__sysctl 156
#endif
#ifndef __NR_prctl
#define __NR_prctl 157
#endif
#ifndef __NR_arch_prctl
#define __NR_arch_prctl 158
#endif
#ifndef __NR_adjtimex
#define __NR_adjtimex 159
#endif
#ifndef __NR_setrlimit
#define __NR_setrlimit 160
#endif
#ifndef __NR_chroot
#define __NR_chroot 161
#endif
#ifndef __NR_sync
#define __NR_sync 162
#endif
#ifndef __NR_acct
#define __NR_acct 163
#endif
#ifndef __NR_settimeofday
#define __NR_settimeofday 164
#endif
#ifndef __NR_mount
#define __NR_mount 165
#endif
#ifndef __NR_umount2
#define __NR_umount2 166
#endif
#ifndef __NR_swapon
#define __NR_swapon 167
#endif
#ifndef __NR_swapoff
#define __NR_swapoff 168
#endif
#ifndef __NR_reboot
#define __NR_reboot 169
#endif
#ifndef __NR_sethostname
#define __NR_sethostname 170
#endif
#ifndef __NR_setdomainname
#define __NR_setdomainname 171
#endif
#ifndef __NR_iopl
#define __NR_iopl 172
#endif
#ifndef __NR_ioperm
#define __NR_ioperm 173
#endif
#ifndef __NR_create_module
#define __NR_create_module 174
#endif
#ifndef __NR_init_module
#define __NR_init_module 175
#endif
#ifndef __NR_delete_module
#define __NR_delete_module 176
#endif
#ifndef __NR_get_kernel_syms
#define __NR_get_kernel_syms 177
#endif
#ifndef __NR_query_module
#define __NR_query_module 178
#endif
#ifndef __NR_quotactl
#define __NR_quotactl 179
#endif
#ifndef __NR_nfsservctl
#define __NR_nfsservctl 180
#endif
#ifndef __NR_getpmsg
#define __NR_getpmsg 181
#endif
#ifndef __NR_gettid
#define __NR_gettid 186
#endif
#ifndef __NR_readahead
#define __NR_readahead 187
#endif
#ifndef __NR_setxattr
#define __NR_setxattr 188
#endif
#ifndef __NR_lsetxattr
#define __NR_lsetxattr 189
#endif
#ifndef __NR_fsetxattr
#define __NR_fsetxattr 190
#endif
#ifndef __NR_getxattr
#define __NR_getxattr 191
#endif
#ifndef __NR_lgetxattr
#define __NR_lgetxattr 192
#endif
#ifndef __NR_fgetxattr
#define __NR_fgetxattr 193
#endif
#ifndef __NR_listxattr
#define __NR_listxattr 194
#endif
#ifndef __NR_llistxattr
#define __NR_llistxattr 195
#endif
#ifndef __NR_flistxattr
#define __NR_flistxattr 196
#endif
#ifndef __NR_removexattr
#define __NR_removexattr 197
#endif
#ifndef __NR_lremovexattr
#define __NR_lremovexattr 198
#endif
#ifndef __NR_fremovexattr
#define __NR_fremovexattr 199
#endif
#ifndef __NR_tkill
#define __NR_tkill 200
#endif
#ifndef __NR_time
#define __NR_time 201
#endif
#ifndef __NR_futex
#define __NR_futex 202
#endif
#ifndef __NR_sched_setaffinity
#define __NR_sched_setaffinity 203
#endif
#ifndef __NR_sched_getaffinity
#define __NR_sched_getaffinity 204
#endif
#ifndef __NR_set_thread_area
#define __NR_set_thread_area 205
#endif
#ifndef __NR_io_setup
#define __NR_io_setup 206
#endif
#ifndef __NR_io_destroy
#define __NR_io_destroy 207
#endif
#ifndef __NR_io_getevents
#define __NR_io_getevents 208
#endif
#ifndef __NR_io_submit
#define __NR_io_submit 209
#endif
#ifndef __NR_io_cancel
#define __NR_io_cancel 210
#endif
#ifndef __NR_get_thread_area
#define __NR_get_thread_area 211
#endif
#ifndef __NR_lookup_dcookie
#define __NR_lookup_dcookie 212
#endif
#ifndef __NR_epoll_create
#define __NR_epoll_create 213
#endif
#ifndef __NR_epoll_ctl_old
#define __NR_epoll_ctl_old 214
#endif
#ifndef __NR_epoll_wait_old
#define __NR_epoll_wait_old 215
#endif
#ifndef __NR_remap_file_pages
#define __NR_remap_file_pages 216
#endif
#ifndef __NR_getdents64
#define __NR_getdents64 217
#endif
#ifndef __NR_set_tid_address
#define __NR_set_tid_address 218
#endif
#ifndef __NR_restart_syscall
#define __NR_restart_syscall 219
#endif
#ifndef __NR_semtimedop
#define __NR_semtimedop 220
#endif
#ifndef __NR_fadvise64
#define __NR_fadvise64 221
#endif
#ifndef __NR_timer_create
#define __NR_timer_create 222
#endif
#ifndef __NR_timer_settime
#define __NR_timer_settime 223
#endif
#ifndef __NR_timer_gettime
#define __NR_timer_gettime 224
#endif
#ifndef __NR_timer_getoverrun
#define __NR_timer_getoverrun 225
#endif
#ifndef __NR_timer_delete
#define __NR_timer_delete 226
#endif
#ifndef __NR_clock_settime
#define __NR_clock_settime 227
#endif
#ifndef __NR_clock_gettime
#define __NR_clock_gettime 228
#endif
#ifndef __NR_clock_getres
#define __NR_clock_getres 229
#endif
#ifndef __NR_clock_nanosleep
#define __NR_clock_nanosleep 230
#endif
#ifndef __NR_exit_group
#define __NR_exit_group 231
#endif
#ifndef __NR_epoll_wait
#define __NR_epoll_wait 232
#endif
#ifndef __NR_epoll_ctl
#define __NR_epoll_ctl 233
#endif
#ifndef __NR_tgkill
#define __NR_tgkill 234
#endif
#ifndef __NR_utimes
#define __NR_utimes 235
#endif
#ifndef __NR_mbind
#define __NR_mbind 237
#endif
#ifndef __NR_set_mempolicy
#define __NR_set_mempolicy 238
#endif
#ifndef __NR_get_mempolicy
#define __NR_get_mempolicy 239
#endif
#ifndef __NR_mq_open
#define __NR_mq_open 240
#endif
#ifndef __NR_mq_unlink
#define __NR_mq_unlink 241
#endif
#ifndef __NR_mq_timedsend
#define __NR_mq_timedsend 242
#endif
#ifndef __NR_mq_timedreceive
#define __NR_mq_timedreceive 243
#endif
#ifndef __NR_mq_notify
#define __NR_mq_notify 244
#endif
#ifndef __NR_mq_getsetattr
#define __NR_mq_getsetattr 245
#endif
#ifndef __NR_kexec_load
#define __NR_kexec_load 246
#endif
#ifndef __NR_waitid
#define __NR_waitid 247
#endif
#ifndef __NR_add_key
#define __NR_add_key 248
#endif
#ifndef __NR_request_key
#define __NR_request_key 249
#endif
#ifndef __NR_keyctl
#define __NR_keyctl 250
#endif
#ifndef __NR_ioprio_set
#define __NR_ioprio_set 251
#endif
#ifndef __NR_ioprio_get
#define __NR_ioprio_get 252
#endif
#ifndef __NR_inotify_init
#define __NR_inotify_init 253
#endif
#ifndef __NR_inotify_add_watch
#define __NR_inotify_add_watch 254
#endif
#ifndef __NR_inotify_rm_watch
#define __NR_inotify_rm_watch 255
#endif
#ifndef __NR_migrate_pages
#define __NR_migrate_pages 256
#endif
#ifndef __NR_openat
#define __NR_openat 257
#endif
#ifndef __NR_mkdirat
#define __NR_mkdirat 258
#endif
#ifndef __NR_mknodat
#define __NR_mknodat 259
#endif
#ifndef __NR_fchownat
#define __NR_fchownat 260
#endif
#ifndef __NR_futimesat
#define __NR_futimesat 261
#endif
#ifndef __NR_newfstatat
#define __NR_newfstatat 262
#endif
#ifndef __NR_unlinkat
#define __NR_unlinkat 263
#endif
#ifndef __NR_renameat
#define __NR_renameat 264
#endif
#ifndef __NR_linkat
#define __NR_linkat 265
#endif
#ifndef __NR_symlinkat
#define __NR_symlinkat 266
#endif
#ifndef __NR_readlinkat
#define __NR_readlinkat 267
#endif
#ifndef __NR_fchmodat
#define __NR_fchmodat 268
#endif
#ifndef __NR_faccessat
#define __NR_faccessat 269
#endif
#ifndef __NR_pselect6
#define __NR_pselect6 270
#endif
#ifndef __NR_ppoll
#define __NR_ppoll 271
#endif
#ifndef __NR_unshare
#define __NR_unshare 272
#endif
#ifndef __NR_set_robust_list
#define __NR_set_robust_list 273
#endif
#ifndef __NR_get_robust_list
#define __NR_get_robust_list 274
#endif
#ifndef __NR_splice
#define __NR_splice 275
#endif
#ifndef __NR_tee
#define __NR_tee 276
#endif
#ifndef __NR_sync_file_range
#define __NR_sync_file_range 277
#endif
#ifndef __NR_vmsplice
#define __NR_vmsplice 278
#endif
#ifndef __NR_move_pages
#define __NR_move_pages 279
#endif
#ifndef __NR_utimensat
#define __NR_utimensat 280
#endif
#ifndef __NR_epoll_pwait
#define __NR_epoll_pwait 281
#endif
#ifndef __NR_signalfd
#define __NR_signalfd 282
#endif
#ifndef __NR_timerfd_create
#define __NR_timerfd_create 283
#endif
#ifndef __NR_eventfd
#define __NR_eventfd 284
#endif
#ifndef __NR_fallocate
#define __NR_fallocate 285
#endif
#ifndef __NR_timerfd_settime
#define __NR_timerfd_settime 286
#endif
#ifndef __NR_timerfd_gettime
#define __NR_timerfd_gettime 287
#endif
#ifndef __NR_accept4
#define __NR_accept4 288
#endif
#ifndef __NR_signalfd4
#define __NR_signalfd4 289
#endif
#ifndef __NR_eventfd2
#define __NR_eventfd2 290
#endif
#ifndef __NR_epoll_create1
#define __NR_epoll_create1 291
#endif
#ifndef __NR_dup3
#define __NR_dup3 292
#endif
#ifndef __NR_pipe2
#define __NR_pipe2 293
#endif
#ifndef __NR_inotify_init1
#define __NR_inotify_init1 294
#endif
#ifndef __NR_preadv
#define __NR_preadv 295
#endif
#ifndef __NR_pwritev
#define __NR_pwritev 296
#endif
#ifndef __NR_rt_tgsigqueueinfo
#define __NR_rt_tgsigqueueinfo 297
#endif
#ifndef __NR_perf_event_open
#define __NR_perf_event_open 298
#endif
#ifndef __NR_recvmmsg
#define __NR_recvmmsg 299
#endif
#ifndef __NR_fanotify_init
#define __NR_fanotify_init 300
#endif
#ifndef __NR_fanotify_mark
#define __NR_fanotify_mark 301
#endif
#ifndef __NR_prlimit64
#define __NR_prlimit64 302
#endif
#ifndef __NR_name_to_handle_at
#define __NR_name_to_handle_at 303
#endif
#ifndef __NR_open_by_handle_at
#define __NR_open_by_handle_at 304
#endif
#ifndef __NR_clock_adjtime
#define __NR_clock_adjtime 305
#endif
#ifndef __NR_syncfs
#define __NR_syncfs 306
#endif
#ifndef __NR_sendmmsg
#define __NR_sendmmsg 307
#endif
#ifndef __NR_setns
#define __NR_setns 308
#endif
#ifndef __NR_getcpu
#define __NR_getcpu 309
#endif
#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 310
#endif
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 311
#endif
#ifndef __NR_kcmp
#define __NR_kcmp 312
#endif
#ifndef __NR_finit_module
#define __NR_finit_module 313
#endif
#ifndef __NR_sched_setattr
#define __NR_sched_setattr 314
#endif
#ifndef __NR_sched_getattr
#define __NR_sched_getattr 315
#endif
#ifndef __NR_renameat2
#define __NR_renameat2 316
#endif
#ifndef __NR_seccomp
#define __NR_seccomp 317
#endif
#ifndef __NR_getrandom
#define __NR_getrandom 318
#endif
#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif
#ifndef __NR_kexec_file_load
#define __NR_kexec_file_load 320
#endif
#ifndef __NR_bpf
#define __NR_bpf 321
#endif
#ifndef __NR_execveat
#define __NR_execveat 322
#endif
#ifndef __NR_userfaultfd
#define __NR_userfaultfd 323
#endif
#ifndef __NR_membarrier
#define __NR_membarrier 324
#endif
#ifndef __NR_mlock2
#define __NR_mlock2 325
#endif
#ifndef __NR_copy_file_range
#define __NR_copy_file_range 326
#endif
#ifndef __NR_preadv2
#define __NR_preadv2 327
#endif
#ifndef __NR_pwritev2
#define __NR_pwritev2 328
#endif
#ifndef __NR_pkey_mprotect
#define __NR_pkey_mprotect 329
#endif
#ifndef __NR_pkey_alloc
#define __NR_pkey_alloc 330
#endif
#ifndef __NR_pkey_free
#define __NR_pkey_free 331
#endif
#ifndef __NR_statx
#define __NR_statx 332
#endif
#ifndef __NR_io_pgetevents
#define __NR_io_pgetevents 333
#endif
#ifndef __NR_rseq
#define __NR_rseq 334
#endif
#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif
#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif
#ifndef __NR_open_tree
#define __NR_open_tree 428
#endif
#ifndef __NR_move_mount
#define __NR_move_mount 429
#endif
#ifndef __NR_fsopen
#define __NR_fsopen 430
#endif
#ifndef __NR_fsconfig
#define __NR_fsconfig 431
#endif
#ifndef __NR_fsmount
#define __NR_fsmount 432
#endif
#ifndef __NR_fspick
#define __NR_fspick 433
#endif
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_clone3
#define __NR_clone3 435
#endif
#ifndef __NR_close_range
#define __NR_close_range 436
#endif
#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif
#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif
#ifndef __NR_process_madvise
#define __NR_process_madvise 440
#endif
#ifndef __NR_epoll_pwait2
#define __NR_epoll_pwait2 441
#endif
#ifndef __NR_mount_setattr
#define __NR_mount_setattr 442
#endif
#ifndef __NR_quotactl_fd
#define __NR_quotactl_fd 443
#endif
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif
#ifndef __NR_memfd_secret
#define __NR_memfd_secret 447
#endif
#ifndef __NR_process_mrelease
#define __NR_process_mrelease 448
#endif
#ifndef __NR_futex_waitv
#define __NR_futex_waitv 449
#endif
#ifndef __NR_set_mempolicy_home_node
#define __NR_set_mempolicy_home_node 450
#endif
