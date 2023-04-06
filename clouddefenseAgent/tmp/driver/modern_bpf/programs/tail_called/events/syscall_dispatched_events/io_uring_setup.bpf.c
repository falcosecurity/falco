/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(io_uring_setup_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, IO_URING_SETUP_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_IO_URING_SETUP_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameters to collect.

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(io_uring_setup_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, IO_URING_SETUP_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_IO_URING_SETUP_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: entries (type: PT_UINT32) */
	u32 entries = (u32)extract__syscall_argument(regs, 0);
	ringbuf__store_u32(&ringbuf, entries);

	/* Get the second syscall argument that is a `struct io_uring_params*`
	 * This struct is defined since kernel release 5.1
	 */
	unsigned long params_pointer = extract__syscall_argument(regs, 1);
	struct io_uring_params params = {0};
	bpf_probe_read_user((void *)&params, bpf_core_type_size(struct io_uring_params), (void *)params_pointer);

	/* Parameter 3: sq_entries (type: PT_UINT32) */
	ringbuf__store_u32(&ringbuf, params.sq_entries);

	/* Parameter 4: cq_entries (type: PT_UINT32) */
	ringbuf__store_u32(&ringbuf, params.cq_entries);

	/* Parameter 5: flags (type: PT_FLAGS32) */
	ringbuf__store_u32(&ringbuf, (u32)io_uring_setup_flags_to_scap(params.flags));

	/* Parameter 6: sq_thread_cpu (type: PT_UINT32) */
	ringbuf__store_u32(&ringbuf, params.sq_thread_cpu);

	/* Parameter 7: sq_thread_idle (type: PT_UINT32) */
	ringbuf__store_u32(&ringbuf, params.sq_thread_idle);

	/* Parameter 8: features (type: PT_FLAGS32) */
	ringbuf__store_u32(&ringbuf, (u32)io_uring_setup_feats_to_scap(params.features));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
