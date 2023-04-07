/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/* These BPF programs are used for `signalfd` and `signalfd4` syscalls. */

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(signalfd_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SIGNALFD_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SIGNALFD_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	s32 fd = (s32)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (s64)fd);

	/* Parameter 2: mask (type: PT_UINT32) */
	/* Like in the old probe we send `0`. */
	ringbuf__store_u32(&ringbuf, 0);

	/* Parameter 3: flags (type: PT_FLAGS8) */
	/// TODO: this are not flags, but it is a sizemask,
	/// please see here for more deatails:
	/// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/signalfd.c#n302
	/// We need to create 2 separate events for `signalfd` and `signalfd4`.
	/* Like in the old probe we send `0`. */
	ringbuf__store_u8(&ringbuf, 0);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(signalfd_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SIGNALFD_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SIGNALFD_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_FD)*/
	ringbuf__store_s64(&ringbuf, ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
