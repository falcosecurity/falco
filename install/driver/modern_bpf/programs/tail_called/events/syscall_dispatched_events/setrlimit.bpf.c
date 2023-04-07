/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(setrlimit_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SETRLIMIT_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SETRLIMIT_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: resource (type: PT_ENUMFLAGS8) */
	unsigned long resource = extract__syscall_argument(regs, 0);
	ringbuf__store_u8(&ringbuf, rlimit_resource_to_scap(resource));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(setrlimit_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SETRLIMIT_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SETRLIMIT_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	ringbuf__store_s64(&ringbuf, ret);

	struct rlimit rl = {0};
	unsigned long rlimit_pointer = extract__syscall_argument(regs, 1);
	bpf_probe_read_user((void *)&rl, bpf_core_type_size(struct rlimit), (void *)rlimit_pointer);

	/* Parameter 2: cur (type: PT_INT64)*/
	ringbuf__store_s64(&ringbuf, rl.rlim_cur);

	/* Parameter 3: max (type: PT_INT64)*/
	ringbuf__store_s64(&ringbuf, rl.rlim_max);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
