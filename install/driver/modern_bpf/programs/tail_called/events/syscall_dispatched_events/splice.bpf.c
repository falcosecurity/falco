/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(splice_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SPLICE_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SPLICE_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd_in (type: PT_FD) */
	s32 fd_in = (s32)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (s64)fd_in);

	/* Parameter 2: fd_out (type: PT_FD) */
	s32 fd_out = (s32)extract__syscall_argument(regs, 2);
	ringbuf__store_s64(&ringbuf, (s64)fd_out);

	/* Parameter 3: size (type: PT_UINT64) */
	u64 size = extract__syscall_argument(regs, 4);
	ringbuf__store_u64(&ringbuf, size);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	u32 flags = extract__syscall_argument(regs, 5);
	ringbuf__store_u32(&ringbuf, splice_flags_to_scap(flags));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(splice_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SPLICE_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SPLICE_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, (s64)ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
