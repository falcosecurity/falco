/*
* Copyright (C) 2022 The Falco Authors.
*
* This file is dual licensed under either the MIT or GPL 2. See MIT.txt
* or GPL2.txt for full copies of the license.
*/

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(epoll_create_e,
	    struct pt_regs *regs,
	    long id)
{
       struct ringbuf_struct ringbuf;
       if(!ringbuf__reserve_space(&ringbuf, EPOLL_CREATE_E_SIZE))
       {
	       return 0;
       }

       ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_EPOLL_CREATE_E);

       /*=============================== COLLECT PARAMETERS  ===========================*/

       /* Parameter 1: size (type: PT_INT32) */
       s32 size = (s32)extract__syscall_argument(regs, 0);
       ringbuf__store_s32(&ringbuf, size);

       /*=============================== COLLECT PARAMETERS  ===========================*/

       ringbuf__submit_event(&ringbuf);

       return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(epoll_create_x,
	    struct pt_regs *regs,
	    long ret)
{
       struct ringbuf_struct ringbuf;
       if(!ringbuf__reserve_space(&ringbuf, EPOLL_CREATE_X_SIZE))
       {
	       return 0;
       }

       ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_EPOLL_CREATE_X);

       /*=============================== COLLECT PARAMETERS  ===========================*/

       /* Parameter 1: res (type: PT_ERRNO)*/
       ringbuf__store_s64(&ringbuf, ret);

       /*=============================== COLLECT PARAMETERS  ===========================*/

       ringbuf__submit_event(&ringbuf);

       return 0;
}

/*=============================== EXIT EVENT ===========================*/
