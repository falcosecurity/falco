/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

/*=============================== ENTER EVENT ===========================*/

#include <helpers/interfaces/fixed_size_event.h>

SEC("tp_btf/sys_enter")
int BPF_PROG(mprotect_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, MPROTECT_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_MPROTECT_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: addr (type: PT_UINT64) */
	u64 addr = extract__syscall_argument(regs, 0);
	ringbuf__store_u64(&ringbuf, addr);

	/* Parameter 2: length (type: PT_UINT64) */
	u64 length = extract__syscall_argument(regs, 1);
	ringbuf__store_u64(&ringbuf, length);

	/* Parameter 3: prot (type: PT_FLAGS32) */
	u32 flags = extract__syscall_argument(regs, 2);
	ringbuf__store_u32(&ringbuf, prot_flags_to_scap(flags));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(mprotect_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
        if(!ringbuf__reserve_space(&ringbuf, MPROTECT_X_SIZE))
        {
                return 0;
        }

        ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_MPROTECT_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
