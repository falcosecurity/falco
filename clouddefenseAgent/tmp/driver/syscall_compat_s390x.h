#pragma once
#ifndef __NR_exit
#define __NR_exit 1
#endif
#ifndef __NR_fork
#define __NR_fork 2
#endif
#ifndef __NR_read
#define __NR_read 3
#endif
#ifndef __NR_write
#define __NR_write 4
#endif
#ifndef __NR_open
#define __NR_open 5
#endif
#ifndef __NR_close
#define __NR_close 6
#endif
#ifndef __NR_restart_syscall
#define __NR_restart_syscall 7
#endif
#ifndef __NR_creat
#define __NR_creat 8
#endif
#ifndef __NR_link
#define __NR_link 9
#endif
#ifndef __NR_unlink
#define __NR_unlink 10
#endif
#ifndef __NR_execve
#define __NR_execve 11
#endif
#ifndef __NR_chdir
#define __NR_chdir 12
#endif
#ifndef __NR_mknod
#define __NR_mknod 14
#endif
#ifndef __NR_chmod
#define __NR_chmod 15
#endif
#ifndef __NR_lseek
#define __NR_lseek 19
#endif
#ifndef __NR_getpid
#define __NR_getpid 20
#endif
#ifndef __NR_mount
#define __NR_mount 21
#endif
#ifndef __NR_umount
#define __NR_umount 22
#endif
#ifndef __NR_ptrace
#define __NR_ptrace 26
#endif
#ifndef __NR_alarm
#define __NR_alarm 27
#endif
#ifndef __NR_pause
#define __NR_pause 29
#endif
#ifndef __NR_utime
#define __NR_utime 30
#endif
#ifndef __NR_access
#define __NR_access 33
#endif
#ifndef __NR_nice
#define __NR_nice 34
#endif
#ifndef __NR_sync
#define __NR_sync 36
#endif
#ifndef __NR_kill
#define __NR_kill 37
#endif
#ifndef __NR_rename
#define __NR_rename 38
#endif
#ifndef __NR_mkdir
#define __NR_mkdir 39
#endif
#ifndef __NR_rmdir
#define __NR_rmdir 40
#endif
#ifndef __NR_dup
#define __NR_dup 41
#endif
#ifndef __NR_pipe
#define __NR_pipe 42
#endif
#ifndef __NR_times
#define __NR_times 43
#endif
#ifndef __NR_brk
#define __NR_brk 45
#endif
#ifndef __NR_signal
#define __NR_signal 48
#endif
#ifndef __NR_acct
#define __NR_acct 51
#endif
#ifndef __NR_umount2
#define __NR_umount2 52
#endif
#ifndef __NR_ioctl
#define __NR_ioctl 54
#endif
#ifndef __NR_fcntl
#define __NR_fcntl 55
#endif
#ifndef __NR_setpgid
#define __NR_setpgid 57
#endif
#ifndef __NR_umask
#define __NR_umask 60
#endif
#ifndef __NR_chroot
#define __NR_chroot 61
#endif
#ifndef __NR_ustat
#define __NR_ustat 62
#endif
#ifndef __NR_dup2
#define __NR_dup2 63
#endif
#ifndef __NR_getppid
#define __NR_getppid 64
#endif
#ifndef __NR_getpgrp
#define __NR_getpgrp 65
#endif
#ifndef __NR_setsid
#define __NR_setsid 66
#endif
#ifndef __NR_sigaction
#define __NR_sigaction 67
#endif
#ifndef __NR_sigsuspend
#define __NR_sigsuspend 72
#endif
#ifndef __NR_sigpending
#define __NR_sigpending 73
#endif
#ifndef __NR_sethostname
#define __NR_sethostname 74
#endif
#ifndef __NR_setrlimit
#define __NR_setrlimit 75
#endif
#ifndef __NR_getrusage
#define __NR_getrusage 77
#endif
#ifndef __NR_gettimeofday
#define __NR_gettimeofday 78
#endif
#ifndef __NR_settimeofday
#define __NR_settimeofday 79
#endif
#ifndef __NR_symlink
#define __NR_symlink 83
#endif
#ifndef __NR_readlink
#define __NR_readlink 85
#endif
#ifndef __NR_uselib
#define __NR_uselib 86
#endif
#ifndef __NR_swapon
#define __NR_swapon 87
#endif
#ifndef __NR_reboot
#define __NR_reboot 88
#endif
#ifndef __NR_readdir
#define __NR_readdir 89
#endif
#ifndef __NR_mmap
#define __NR_mmap 90
#endif
#ifndef __NR_munmap
#define __NR_munmap 91
#endif
#ifndef __NR_truncate
#define __NR_truncate 92
#endif
#ifndef __NR_ftruncate
#define __NR_ftruncate 93
#endif
#ifndef __NR_fchmod
#define __NR_fchmod 94
#endif
#ifndef __NR_getpriority
#define __NR_getpriority 96
#endif
#ifndef __NR_setpriority
#define __NR_setpriority 97
#endif
#ifndef __NR_statfs
#define __NR_statfs 99
#endif
#ifndef __NR_fstatfs
#define __NR_fstatfs 100
#endif
#ifndef __NR_socketcall
#define __NR_socketcall 102
#endif
#ifndef __NR_syslog
#define __NR_syslog 103
#endif
#ifndef __NR_setitimer
#define __NR_setitimer 104
#endif
#ifndef __NR_getitimer
#define __NR_getitimer 105
#endif
#ifndef __NR_stat
#define __NR_stat 106
#endif
#ifndef __NR_lstat
#define __NR_lstat 107
#endif
#ifndef __NR_fstat
#define __NR_fstat 108
#endif
#ifndef __NR_lookup_dcookie
#define __NR_lookup_dcookie 110
#endif
#ifndef __NR_vhangup
#define __NR_vhangup 111
#endif
#ifndef __NR_idle
#define __NR_idle 112
#endif
#ifndef __NR_wait4
#define __NR_wait4 114
#endif
#ifndef __NR_swapoff
#define __NR_swapoff 115
#endif
#ifndef __NR_sysinfo
#define __NR_sysinfo 116
#endif
#ifndef __NR_ipc
#define __NR_ipc 117
#endif
#ifndef __NR_fsync
#define __NR_fsync 118
#endif
#ifndef __NR_sigreturn
#define __NR_sigreturn 119
#endif
#ifndef __NR_clone
#define __NR_clone 120
#endif
#ifndef __NR_setdomainname
#define __NR_setdomainname 121
#endif
#ifndef __NR_uname
#define __NR_uname 122
#endif
#ifndef __NR_adjtimex
#define __NR_adjtimex 124
#endif
#ifndef __NR_mprotect
#define __NR_mprotect 125
#endif
#ifndef __NR_sigprocmask
#define __NR_sigprocmask 126
#endif
#ifndef __NR_create_module
#define __NR_create_module 127
#endif
#ifndef __NR_init_module
#define __NR_init_module 128
#endif
#ifndef __NR_delete_module
#define __NR_delete_module 129
#endif
#ifndef __NR_get_kernel_syms
#define __NR_get_kernel_syms 130
#endif
#ifndef __NR_quotactl
#define __NR_quotactl 131
#endif
#ifndef __NR_getpgid
#define __NR_getpgid 132
#endif
#ifndef __NR_fchdir
#define __NR_fchdir 133
#endif
#ifndef __NR_bdflush
#define __NR_bdflush 134
#endif
#ifndef __NR_sysfs
#define __NR_sysfs 135
#endif
#ifndef __NR_personality
#define __NR_personality 136
#endif
#ifndef __NR_getdents
#define __NR_getdents 141
#endif
#ifndef __NR_select
#define __NR_select 142
#endif
#ifndef __NR_flock
#define __NR_flock 143
#endif
#ifndef __NR_msync
#define __NR_msync 144
#endif
#ifndef __NR_readv
#define __NR_readv 145
#endif
#ifndef __NR_writev
#define __NR_writev 146
#endif
#ifndef __NR_getsid
#define __NR_getsid 147
#endif
#ifndef __NR_fdatasync
#define __NR_fdatasync 148
#endif
#ifndef __NR__sysctl
#define __NR__sysctl 149
#endif
#ifndef __NR_mlock
#define __NR_mlock 150
#endif
#ifndef __NR_munlock
#define __NR_munlock 151
#endif
#ifndef __NR_mlockall
#define __NR_mlockall 152
#endif
#ifndef __NR_munlockall
#define __NR_munlockall 153
#endif
#ifndef __NR_sched_setparam
#define __NR_sched_setparam 154
#endif
#ifndef __NR_sched_getparam
#define __NR_sched_getparam 155
#endif
#ifndef __NR_sched_setscheduler
#define __NR_sched_setscheduler 156
#endif
#ifndef __NR_sched_getscheduler
#define __NR_sched_getscheduler 157
#endif
#ifndef __NR_sched_yield
#define __NR_sched_yield 158
#endif
#ifndef __NR_sched_get_priority_max
#define __NR_sched_get_priority_max 159
#endif
#ifndef __NR_sched_get_priority_min
#define __NR_sched_get_priority_min 160
#endif
#ifndef __NR_sched_rr_get_interval
#define __NR_sched_rr_get_interval 161
#endif
#ifndef __NR_nanosleep
#define __NR_nanosleep 162
#endif
#ifndef __NR_mremap
#define __NR_mremap 163
#endif
#ifndef __NR_query_module
#define __NR_query_module 167
#endif
#ifndef __NR_poll
#define __NR_poll 168
#endif
#ifndef __NR_nfsservctl
#define __NR_nfsservctl 169
#endif
#ifndef __NR_prctl
#define __NR_prctl 172
#endif
#ifndef __NR_rt_sigreturn
#define __NR_rt_sigreturn 173
#endif
#ifndef __NR_rt_sigaction
#define __NR_rt_sigaction 174
#endif
#ifndef __NR_rt_sigprocmask
#define __NR_rt_sigprocmask 175
#endif
#ifndef __NR_rt_sigpending
#define __NR_rt_sigpending 176
#endif
#ifndef __NR_rt_sigtimedwait
#define __NR_rt_sigtimedwait 177
#endif
#ifndef __NR_rt_sigqueueinfo
#define __NR_rt_sigqueueinfo 178
#endif
#ifndef __NR_rt_sigsuspend
#define __NR_rt_sigsuspend 179
#endif
#ifndef __NR_pread64
#define __NR_pread64 180
#endif
#ifndef __NR_pwrite64
#define __NR_pwrite64 181
#endif
#ifndef __NR_getcwd
#define __NR_getcwd 183
#endif
#ifndef __NR_capget
#define __NR_capget 184
#endif
#ifndef __NR_capset
#define __NR_capset 185
#endif
#ifndef __NR_sigaltstack
#define __NR_sigaltstack 186
#endif
#ifndef __NR_sendfile
#define __NR_sendfile 187
#endif
#ifndef __NR_getpmsg
#define __NR_getpmsg 188
#endif
#ifndef __NR_vfork
#define __NR_vfork 190
#endif
#ifndef __NR_getrlimit
#define __NR_getrlimit 191
#endif
#ifndef __NR_lchown
#define __NR_lchown 198
#endif
#ifndef __NR_getuid
#define __NR_getuid 199
#endif
#ifndef __NR_getgid
#define __NR_getgid 200
#endif
#ifndef __NR_geteuid
#define __NR_geteuid 201
#endif
#ifndef __NR_getegid
#define __NR_getegid 202
#endif
#ifndef __NR_setreuid
#define __NR_setreuid 203
#endif
#ifndef __NR_setregid
#define __NR_setregid 204
#endif
#ifndef __NR_getgroups
#define __NR_getgroups 205
#endif
#ifndef __NR_setgroups
#define __NR_setgroups 206
#endif
#ifndef __NR_fchown
#define __NR_fchown 207
#endif
#ifndef __NR_setresuid
#define __NR_setresuid 208
#endif
#ifndef __NR_getresuid
#define __NR_getresuid 209
#endif
#ifndef __NR_setresgid
#define __NR_setresgid 210
#endif
#ifndef __NR_getresgid
#define __NR_getresgid 211
#endif
#ifndef __NR_chown
#define __NR_chown 212
#endif
#ifndef __NR_setuid
#define __NR_setuid 213
#endif
#ifndef __NR_setgid
#define __NR_setgid 214
#endif
#ifndef __NR_setfsuid
#define __NR_setfsuid 215
#endif
#ifndef __NR_setfsgid
#define __NR_setfsgid 216
#endif
#ifndef __NR_pivot_root
#define __NR_pivot_root 217
#endif
#ifndef __NR_mincore
#define __NR_mincore 218
#endif
#ifndef __NR_madvise
#define __NR_madvise 219
#endif
#ifndef __NR_getdents64
#define __NR_getdents64 220
#endif
#ifndef __NR_readahead
#define __NR_readahead 222
#endif
#ifndef __NR_setxattr
#define __NR_setxattr 224
#endif
#ifndef __NR_lsetxattr
#define __NR_lsetxattr 225
#endif
#ifndef __NR_fsetxattr
#define __NR_fsetxattr 226
#endif
#ifndef __NR_getxattr
#define __NR_getxattr 227
#endif
#ifndef __NR_lgetxattr
#define __NR_lgetxattr 228
#endif
#ifndef __NR_fgetxattr
#define __NR_fgetxattr 229
#endif
#ifndef __NR_listxattr
#define __NR_listxattr 230
#endif
#ifndef __NR_llistxattr
#define __NR_llistxattr 231
#endif
#ifndef __NR_flistxattr
#define __NR_flistxattr 232
#endif
#ifndef __NR_removexattr
#define __NR_removexattr 233
#endif
#ifndef __NR_lremovexattr
#define __NR_lremovexattr 234
#endif
#ifndef __NR_fremovexattr
#define __NR_fremovexattr 235
#endif
#ifndef __NR_gettid
#define __NR_gettid 236
#endif
#ifndef __NR_tkill
#define __NR_tkill 237
#endif
#ifndef __NR_futex
#define __NR_futex 238
#endif
#ifndef __NR_sched_setaffinity
#define __NR_sched_setaffinity 239
#endif
#ifndef __NR_sched_getaffinity
#define __NR_sched_getaffinity 240
#endif
#ifndef __NR_tgkill
#define __NR_tgkill 241
#endif
#ifndef __NR_io_setup
#define __NR_io_setup 243
#endif
#ifndef __NR_io_destroy
#define __NR_io_destroy 244
#endif
#ifndef __NR_io_getevents
#define __NR_io_getevents 245
#endif
#ifndef __NR_io_submit
#define __NR_io_submit 246
#endif
#ifndef __NR_io_cancel
#define __NR_io_cancel 247
#endif
#ifndef __NR_exit_group
#define __NR_exit_group 248
#endif
#ifndef __NR_epoll_create
#define __NR_epoll_create 249
#endif
#ifndef __NR_epoll_ctl
#define __NR_epoll_ctl 250
#endif
#ifndef __NR_epoll_wait
#define __NR_epoll_wait 251
#endif
#ifndef __NR_set_tid_address
#define __NR_set_tid_address 252
#endif
#ifndef __NR_fadvise64
#define __NR_fadvise64 253
#endif
#ifndef __NR_timer_create
#define __NR_timer_create 254
#endif
#ifndef __NR_timer_settime
#define __NR_timer_settime 255
#endif
#ifndef __NR_timer_gettime
#define __NR_timer_gettime 256
#endif
#ifndef __NR_timer_getoverrun
#define __NR_timer_getoverrun 257
#endif
#ifndef __NR_timer_delete
#define __NR_timer_delete 258
#endif
#ifndef __NR_clock_settime
#define __NR_clock_settime 259
#endif
#ifndef __NR_clock_gettime
#define __NR_clock_gettime 260
#endif
#ifndef __NR_clock_getres
#define __NR_clock_getres 261
#endif
#ifndef __NR_clock_nanosleep
#define __NR_clock_nanosleep 262
#endif
#ifndef __NR_statfs64
#define __NR_statfs64 265
#endif
#ifndef __NR_fstatfs64
#define __NR_fstatfs64 266
#endif
#ifndef __NR_remap_file_pages
#define __NR_remap_file_pages 267
#endif
#ifndef __NR_mbind
#define __NR_mbind 268
#endif
#ifndef __NR_get_mempolicy
#define __NR_get_mempolicy 269
#endif
#ifndef __NR_set_mempolicy
#define __NR_set_mempolicy 270
#endif
#ifndef __NR_mq_open
#define __NR_mq_open 271
#endif
#ifndef __NR_mq_unlink
#define __NR_mq_unlink 272
#endif
#ifndef __NR_mq_timedsend
#define __NR_mq_timedsend 273
#endif
#ifndef __NR_mq_timedreceive
#define __NR_mq_timedreceive 274
#endif
#ifndef __NR_mq_notify
#define __NR_mq_notify 275
#endif
#ifndef __NR_mq_getsetattr
#define __NR_mq_getsetattr 276
#endif
#ifndef __NR_kexec_load
#define __NR_kexec_load 277
#endif
#ifndef __NR_add_key
#define __NR_add_key 278
#endif
#ifndef __NR_request_key
#define __NR_request_key 279
#endif
#ifndef __NR_keyctl
#define __NR_keyctl 280
#endif
#ifndef __NR_waitid
#define __NR_waitid 281
#endif
#ifndef __NR_ioprio_set
#define __NR_ioprio_set 282
#endif
#ifndef __NR_ioprio_get
#define __NR_ioprio_get 283
#endif
#ifndef __NR_inotify_init
#define __NR_inotify_init 284
#endif
#ifndef __NR_inotify_add_watch
#define __NR_inotify_add_watch 285
#endif
#ifndef __NR_inotify_rm_watch
#define __NR_inotify_rm_watch 286
#endif
#ifndef __NR_migrate_pages
#define __NR_migrate_pages 287
#endif
#ifndef __NR_openat
#define __NR_openat 288
#endif
#ifndef __NR_mkdirat
#define __NR_mkdirat 289
#endif
#ifndef __NR_mknodat
#define __NR_mknodat 290
#endif
#ifndef __NR_fchownat
#define __NR_fchownat 291
#endif
#ifndef __NR_futimesat
#define __NR_futimesat 292
#endif
#ifndef __NR_newfstatat
#define __NR_newfstatat 293
#endif
#ifndef __NR_unlinkat
#define __NR_unlinkat 294
#endif
#ifndef __NR_renameat
#define __NR_renameat 295
#endif
#ifndef __NR_linkat
#define __NR_linkat 296
#endif
#ifndef __NR_symlinkat
#define __NR_symlinkat 297
#endif
#ifndef __NR_readlinkat
#define __NR_readlinkat 298
#endif
#ifndef __NR_fchmodat
#define __NR_fchmodat 299
#endif
#ifndef __NR_faccessat
#define __NR_faccessat 300
#endif
#ifndef __NR_pselect6
#define __NR_pselect6 301
#endif
#ifndef __NR_ppoll
#define __NR_ppoll 302
#endif
#ifndef __NR_unshare
#define __NR_unshare 303
#endif
#ifndef __NR_set_robust_list
#define __NR_set_robust_list 304
#endif
#ifndef __NR_get_robust_list
#define __NR_get_robust_list 305
#endif
#ifndef __NR_splice
#define __NR_splice 306
#endif
#ifndef __NR_sync_file_range
#define __NR_sync_file_range 307
#endif
#ifndef __NR_tee
#define __NR_tee 308
#endif
#ifndef __NR_vmsplice
#define __NR_vmsplice 309
#endif
#ifndef __NR_move_pages
#define __NR_move_pages 310
#endif
#ifndef __NR_getcpu
#define __NR_getcpu 311
#endif
#ifndef __NR_epoll_pwait
#define __NR_epoll_pwait 312
#endif
#ifndef __NR_utimes
#define __NR_utimes 313
#endif
#ifndef __NR_fallocate
#define __NR_fallocate 314
#endif
#ifndef __NR_utimensat
#define __NR_utimensat 315
#endif
#ifndef __NR_signalfd
#define __NR_signalfd 316
#endif
#ifndef __NR_timerfd
#define __NR_timerfd 317
#endif
#ifndef __NR_eventfd
#define __NR_eventfd 318
#endif
#ifndef __NR_timerfd_create
#define __NR_timerfd_create 319
#endif
#ifndef __NR_timerfd_settime
#define __NR_timerfd_settime 320
#endif
#ifndef __NR_timerfd_gettime
#define __NR_timerfd_gettime 321
#endif
#ifndef __NR_signalfd4
#define __NR_signalfd4 322
#endif
#ifndef __NR_eventfd2
#define __NR_eventfd2 323
#endif
#ifndef __NR_inotify_init1
#define __NR_inotify_init1 324
#endif
#ifndef __NR_pipe2
#define __NR_pipe2 325
#endif
#ifndef __NR_dup3
#define __NR_dup3 326
#endif
#ifndef __NR_epoll_create1
#define __NR_epoll_create1 327
#endif
#ifndef __NR_preadv
#define __NR_preadv 328
#endif
#ifndef __NR_pwritev
#define __NR_pwritev 329
#endif
#ifndef __NR_rt_tgsigqueueinfo
#define __NR_rt_tgsigqueueinfo 330
#endif
#ifndef __NR_perf_event_open
#define __NR_perf_event_open 331
#endif
#ifndef __NR_fanotify_init
#define __NR_fanotify_init 332
#endif
#ifndef __NR_fanotify_mark
#define __NR_fanotify_mark 333
#endif
#ifndef __NR_prlimit64
#define __NR_prlimit64 334
#endif
#ifndef __NR_name_to_handle_at
#define __NR_name_to_handle_at 335
#endif
#ifndef __NR_open_by_handle_at
#define __NR_open_by_handle_at 336
#endif
#ifndef __NR_clock_adjtime
#define __NR_clock_adjtime 337
#endif
#ifndef __NR_syncfs
#define __NR_syncfs 338
#endif
#ifndef __NR_setns
#define __NR_setns 339
#endif
#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 340
#endif
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 341
#endif
#ifndef __NR_s390_runtime_instr
#define __NR_s390_runtime_instr 342
#endif
#ifndef __NR_kcmp
#define __NR_kcmp 343
#endif
#ifndef __NR_finit_module
#define __NR_finit_module 344
#endif
#ifndef __NR_sched_setattr
#define __NR_sched_setattr 345
#endif
#ifndef __NR_sched_getattr
#define __NR_sched_getattr 346
#endif
#ifndef __NR_renameat2
#define __NR_renameat2 347
#endif
#ifndef __NR_seccomp
#define __NR_seccomp 348
#endif
#ifndef __NR_getrandom
#define __NR_getrandom 349
#endif
#ifndef __NR_memfd_create
#define __NR_memfd_create 350
#endif
#ifndef __NR_bpf
#define __NR_bpf 351
#endif
#ifndef __NR_s390_pci_mmio_write
#define __NR_s390_pci_mmio_write 352
#endif
#ifndef __NR_s390_pci_mmio_read
#define __NR_s390_pci_mmio_read 353
#endif
#ifndef __NR_execveat
#define __NR_execveat 354
#endif
#ifndef __NR_userfaultfd
#define __NR_userfaultfd 355
#endif
#ifndef __NR_membarrier
#define __NR_membarrier 356
#endif
#ifndef __NR_recvmmsg
#define __NR_recvmmsg 357
#endif
#ifndef __NR_sendmmsg
#define __NR_sendmmsg 358
#endif
#ifndef __NR_socket
#define __NR_socket 359
#endif
#ifndef __NR_socketpair
#define __NR_socketpair 360
#endif
#ifndef __NR_bind
#define __NR_bind 361
#endif
#ifndef __NR_connect
#define __NR_connect 362
#endif
#ifndef __NR_listen
#define __NR_listen 363
#endif
#ifndef __NR_accept4
#define __NR_accept4 364
#endif
#ifndef __NR_getsockopt
#define __NR_getsockopt 365
#endif
#ifndef __NR_setsockopt
#define __NR_setsockopt 366
#endif
#ifndef __NR_getsockname
#define __NR_getsockname 367
#endif
#ifndef __NR_getpeername
#define __NR_getpeername 368
#endif
#ifndef __NR_sendto
#define __NR_sendto 369
#endif
#ifndef __NR_sendmsg
#define __NR_sendmsg 370
#endif
#ifndef __NR_recvfrom
#define __NR_recvfrom 371
#endif
#ifndef __NR_recvmsg
#define __NR_recvmsg 372
#endif
#ifndef __NR_shutdown
#define __NR_shutdown 373
#endif
#ifndef __NR_mlock2
#define __NR_mlock2 374
#endif
#ifndef __NR_copy_file_range
#define __NR_copy_file_range 375
#endif
#ifndef __NR_preadv2
#define __NR_preadv2 376
#endif
#ifndef __NR_pwritev2
#define __NR_pwritev2 377
#endif
#ifndef __NR_s390_guarded_storage
#define __NR_s390_guarded_storage 378
#endif
#ifndef __NR_statx
#define __NR_statx 379
#endif
#ifndef __NR_s390_sthyi
#define __NR_s390_sthyi 380
#endif
#ifndef __NR_kexec_file_load
#define __NR_kexec_file_load 381
#endif
#ifndef __NR_io_pgetevents
#define __NR_io_pgetevents 382
#endif
#ifndef __NR_rseq
#define __NR_rseq 383
#endif
#ifndef __NR_pkey_mprotect
#define __NR_pkey_mprotect 384
#endif
#ifndef __NR_pkey_alloc
#define __NR_pkey_alloc 385
#endif
#ifndef __NR_pkey_free
#define __NR_pkey_free 386
#endif
#ifndef __NR_semtimedop
#define __NR_semtimedop 392
#endif
#ifndef __NR_semget
#define __NR_semget 393
#endif
#ifndef __NR_semctl
#define __NR_semctl 394
#endif
#ifndef __NR_shmget
#define __NR_shmget 395
#endif
#ifndef __NR_shmctl
#define __NR_shmctl 396
#endif
#ifndef __NR_shmat
#define __NR_shmat 397
#endif
#ifndef __NR_shmdt
#define __NR_shmdt 398
#endif
#ifndef __NR_msgget
#define __NR_msgget 399
#endif
#ifndef __NR_msgsnd
#define __NR_msgsnd 400
#endif
#ifndef __NR_msgrcv
#define __NR_msgrcv 401
#endif
#ifndef __NR_msgctl
#define __NR_msgctl 402
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
#ifndef __NR_process_mrelease
#define __NR_process_mrelease 448
#endif
#ifndef __NR_futex_waitv
#define __NR_futex_waitv 449
#endif
#ifndef __NR_set_mempolicy_home_node
#define __NR_set_mempolicy_home_node 450
#endif
