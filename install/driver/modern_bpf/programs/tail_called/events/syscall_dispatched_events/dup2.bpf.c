/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(dup2_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, DUP2_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_DUP2_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: oldfd (type: PT_FD) */
	s32 oldfd = (s32)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (s64)oldfd);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(dup2_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, DUP2_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_DUP2_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_FD)*/
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: oldfd (type: PT_FD) */
	s32 oldfd = (s32)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (s64)oldfd);

	/* Parameter 3: newfd (type: PT_FD) */
	s32 newfd = (s32)extract__syscall_argument(regs, 1);
	ringbuf__store_s64(&ringbuf, (s64)newfd);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
