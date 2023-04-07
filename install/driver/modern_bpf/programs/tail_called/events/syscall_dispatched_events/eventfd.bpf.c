/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/* These BPF programs are used for `eventfd` and `eventfd2` syscalls. */

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(eventfd_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, EVENTFD_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_EVENTFD_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: initval (type: PT_UINT64) */
	u32 initval = (u32)extract__syscall_argument(regs, 0);
	ringbuf__store_u64(&ringbuf, (u64)initval);

	/* Parameter 2: flags (type: PT_FLAGS32) */
	/// TODO: Right now we don't catch any flag.
	u32 flags = 0;
	ringbuf__store_u32(&ringbuf, flags);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(eventfd_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, EVENTFD_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_EVENTFD_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_FD)*/
	ringbuf__store_s64(&ringbuf, ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
