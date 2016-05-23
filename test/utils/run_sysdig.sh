#!/bin/bash

# Run sysdig excluding all events that aren't used by falco and also
# excluding other high-volume events that aren't essential. This
# results in smaller trace files.

# The remaining arguments are taken from the command line.

exec sudo sysdig not evt.type in '(mprotect,brk,mq_timedreceive,mq_receive,mq_timedsend,mq_send,getrusage,procinfo,rt_sigprocmask,rt_sigaction,ioctl,clock_getres,clock_gettime,clock_nanosleep,clock_settime,close,epoll_create,epoll_create1,epoll_ctl,epoll_pwait,epoll_wait,eventfd,fcntl,fcntl64,fstat,fstat64,fstatat64,fstatfs,fstatfs64,futex,getitimer,gettimeofday,ioprio_get,ioprio_set,llseek,lseek,lstat,lstat64,mmap,mmap2,munmap,nanosleep,poll,ppoll,pread,pread64,preadv,procinfo,pselect6,pwrite,pwrite64,pwritev,read,readv,recv,recvfrom,recvmmsg,recvmsg,sched_yield,select,send,sendfile,sendfile64,sendmmsg,sendmsg,sendto,setitimer,settimeofday,shutdown,splice,stat,stat64,statfs,statfs64,switch,tee,timer_create,timer_delete,timerfd_create,timerfd_gettime,timerfd_settime,timer_getoverrun,timer_gettime,timer_settime,wait4,write,writev) and user.name!=ec2-user' $@
