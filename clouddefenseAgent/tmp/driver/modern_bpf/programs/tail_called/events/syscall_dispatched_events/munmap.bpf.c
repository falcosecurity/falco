/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(munmap_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, MUNMAP_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_MUNMAP_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: addr (type: PT_UINT64) */
	unsigned long val = extract__syscall_argument(regs, 0);
	ringbuf__store_u64(&ringbuf, val);

	/* Parameter 2: length (type: PT_UINT64) */
	val = extract__syscall_argument(regs, 1);
	ringbuf__store_u64(&ringbuf, val);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(munmap_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, MUNMAP_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_MUNMAP_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: ret (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	struct task_struct *task = get_current_task();
	struct mm_struct *mm = NULL;
	READ_TASK_FIELD_INTO(&mm, task, mm);

	u32 vm_size = extract__vm_size(mm);
	u32 rss_size = extract__vm_rss(mm);
	u32 swap_size = extract__vm_swap(mm);

	/* Parameter 2: vm_size (type: PT_UINT32) */
	ringbuf__store_u32(&ringbuf, vm_size);

	/* Parameter 3: vm_rss (type: PT_UINT32) */
	ringbuf__store_u32(&ringbuf, rss_size);

	/* Parameter 4: vm_swap (type: PT_UINT32) */
	ringbuf__store_u32(&ringbuf, swap_size);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
