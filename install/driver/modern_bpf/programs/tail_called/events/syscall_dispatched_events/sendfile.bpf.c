/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(sendfile_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SENDFILE_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SENDFILE_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: out_fd (type: PT_FD) */
	s32 out_fd = (s32)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (s64)out_fd);

	/* Parameter 2: in_fd (type: PT_FD) */
	s32 in_fd = (s32)extract__syscall_argument(regs, 1);
	ringbuf__store_s64(&ringbuf, (s64)in_fd);

	/* Parameter 3: offset (type: PT_UINT64) */
	unsigned long offset = 0;
	unsigned long offset_pointer = extract__syscall_argument(regs, 2);
	bpf_probe_read_user((void *)&offset, sizeof(offset), (void *)offset_pointer);
	ringbuf__store_u64(&ringbuf, offset);

	/* Parameter 4: size (type: PT_UINT64) */
	u64 size = extract__syscall_argument(regs, 3);
	ringbuf__store_u64(&ringbuf, size);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(sendfile_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SENDFILE_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SENDFILE_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: offset (type: PT_UINT64) */
	unsigned long offset = 0;
	unsigned long offset_pointer = extract__syscall_argument(regs, 2);
	bpf_probe_read_user((void *)&offset, sizeof(offset), (void *)offset_pointer);
	ringbuf__store_u64(&ringbuf, offset);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
