/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(mmap2_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, MMAP2_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_MMAP2_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: addr (type: PT_UINT64) */
	unsigned long addr = extract__syscall_argument(regs, 0);
	ringbuf__store_u64(&ringbuf, addr);

	/* Parameter 2: length (type: PT_UINT64) */
	unsigned long length = extract__syscall_argument(regs, 1);
	ringbuf__store_u64(&ringbuf, length);

	/* Parameter 3: prot (type: PT_FLAGS32) */
	unsigned long prot = extract__syscall_argument(regs, 2);
	ringbuf__store_u32(&ringbuf, prot_flags_to_scap(prot));

	/* Parameter 4: flags (type: PT_FLAGS32) */
	unsigned long flags = extract__syscall_argument(regs, 3);
	ringbuf__store_u32(&ringbuf, mmap_flags_to_scap(flags));

	/* Paremeter 5: fd (type: PT_FD) */
	s32 fd = (s32)extract__syscall_argument(regs, 4);
	ringbuf__store_s64(&ringbuf, (s64)fd);

	/* Parameter 6: pgoffset (type: PT_UINT64) */
	unsigned long offset = extract__syscall_argument(regs, 5);
	ringbuf__store_u64(&ringbuf, offset);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(mmap2_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, MMAP2_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_MMAP2_X);

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
