/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(getresuid_e,
	     struct pt_regs *regs,
	     long id)
{
        struct ringbuf_struct ringbuf;
        if(!ringbuf__reserve_space(&ringbuf, GETRESUID_E_SIZE))
        {
                return 0;
        }

        ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_GETRESUID_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(getresuid_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
        if(!ringbuf__reserve_space(&ringbuf, GETRESUID_X_SIZE))
        {
                return 0;
        }

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_GETRESUID_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

        /* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: ruid (type: PT_UID) */
	unsigned long ruid_pointer = extract__syscall_argument(regs, 0);
	uid_t ruid;
	bpf_probe_read_user((void *)&ruid, sizeof(ruid), (void *)ruid_pointer);
	ringbuf__store_u32(&ringbuf, (u32)ruid);

	/* Parameter 3: euid (type: PT_UID) */
	unsigned long euid_pointer = extract__syscall_argument(regs, 1);
	uid_t euid;
	bpf_probe_read_user((void *)&euid, sizeof(euid), (void *)euid_pointer);
	ringbuf__store_u32(&ringbuf, (u32)euid);

	/* Parameter 4: suid (type: PT_UID) */
	unsigned long suid_pointer = extract__syscall_argument(regs, 2);
	uid_t suid;
	bpf_probe_read_user((void *)&suid, sizeof(suid), (void *)suid_pointer);
	ringbuf__store_u32(&ringbuf, (u32)suid);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
