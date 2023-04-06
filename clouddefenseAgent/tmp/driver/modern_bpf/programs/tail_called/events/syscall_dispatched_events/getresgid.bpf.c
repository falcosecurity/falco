/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(getresgid_e,
	     struct pt_regs *regs,
	     long id)
{
        struct ringbuf_struct ringbuf;
        if(!ringbuf__reserve_space(&ringbuf, GETRESGID_E_SIZE))
        {
                return 0;
        }

        ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_GETRESGID_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(getresgid_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
        if(!ringbuf__reserve_space(&ringbuf, GETRESGID_X_SIZE))
        {
                return 0;
        }

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_GETRESGID_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

        /* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: rgid (type: PT_GID) */
	unsigned long rgid_pointer = extract__syscall_argument(regs, 0);
	gid_t rgid;
	bpf_probe_read_user((void *)&rgid, sizeof(rgid), (void *)rgid_pointer);
	ringbuf__store_u32(&ringbuf, (u32)rgid);

	/* Parameter 3: egid (type: PT_GID) */
	unsigned long egid_pointer = extract__syscall_argument(regs, 1);
	gid_t egid;
	bpf_probe_read_user((void *)&egid, sizeof(egid), (void *)egid_pointer);
	ringbuf__store_u32(&ringbuf, (u32)egid);

	/* Parameter 4: sgid (type: PT_GID) */
	unsigned long sgid_pointer = extract__syscall_argument(regs, 2);
	gid_t sgid;
	bpf_probe_read_user((void *)&sgid, sizeof(sgid), (void *)sgid_pointer);
	ringbuf__store_u32(&ringbuf, (u32)sgid);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
