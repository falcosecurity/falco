/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(getgid_e,
	     struct pt_regs *regs,
	     long id)
{
        struct ringbuf_struct ringbuf;
        if(!ringbuf__reserve_space(&ringbuf, GETGID_E_SIZE))
        {
                return 0;
        }

        ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_GETGID_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(getgid_x,
	     struct pt_regs *regs,
	     long ret)
{
        struct ringbuf_struct ringbuf;
        if(!ringbuf__reserve_space(&ringbuf, GETGID_X_SIZE))
        {
                return 0;
        }

        ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_GETGID_X);


	/*=============================== COLLECT PARAMETERS  ===========================*/

        /* Parameter 1: gid (type: PT_GID) */
        ringbuf__store_u32(&ringbuf, (u32)ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
