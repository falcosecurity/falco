/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(prlimit64_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, PRLIMIT64_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_PRLIMIT_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: pid (type: PT_PID) */
	pid_t pid = (s32)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (s64)pid);

	/* Parameter 2: resource (type: PT_ENUMFLAGS8) */
	unsigned long resource = extract__syscall_argument(regs, 1);
	ringbuf__store_u8(&ringbuf, rlimit_resource_to_scap(resource));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(prlimit64_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, PRLIMIT64_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_PRLIMIT_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	struct rlimit new_rlimit = {0};
	unsigned long rlimit_pointer = extract__syscall_argument(regs, 2);
	bpf_probe_read_user((void *)&new_rlimit, bpf_core_type_size(struct rlimit), (void *)rlimit_pointer);

	/* Parameter 2: newcur (type: PT_INT64) */
	ringbuf__store_s64(&ringbuf, new_rlimit.rlim_cur);

	/* Parameter 3: newmax (type: PT_INT64) */
	ringbuf__store_s64(&ringbuf, new_rlimit.rlim_max);

	/* We take the old `rlimit` only if the syscall is successful otherwise this
	 * struct will be not filled by the kernel.
	 */
	struct rlimit old_rlimit = {0};
	if(ret == 0)
	{
		rlimit_pointer = extract__syscall_argument(regs, 3);
		bpf_probe_read_user((void *)&old_rlimit, bpf_core_type_size(struct rlimit), (void *)rlimit_pointer);
	}

	/* Parameter 4: oldcur (type: PT_INT64) */
	ringbuf__store_s64(&ringbuf, old_rlimit.rlim_cur);

	/* Parameter 5: oldmax (type: PT_INT64) */
	ringbuf__store_s64(&ringbuf, old_rlimit.rlim_max);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
