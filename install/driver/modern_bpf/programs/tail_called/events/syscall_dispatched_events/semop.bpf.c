/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(semop_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SEMOP_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SEMOP_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: semid (type: PT_INT32)*/
	s32 semid = (s32)extract__syscall_argument(regs, 0);
	ringbuf__store_s32(&ringbuf, semid);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(semop_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SEMOP_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SEMOP_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: nsops (type: PT_UINT32) */
	u32 nsops = (u32)extract__syscall_argument(regs, 2);
	ringbuf__store_u32(&ringbuf, nsops);

	/* Extract pointer to the `sembuf` struct */
	struct sembuf sops[2] = {0};
	unsigned long sops_pointer = extract__syscall_argument(regs, 1);

	if(ret != 0 || sops_pointer == 0 || nsops == 0)
	{
		/* We send all 0 when one of these is true:
		 * - the syscall fails (ret != 0)
		 * - `sops_pointer` is NULL
		 * - `nsops` is 0
		 */
	}
	else if(nsops == 1)
	{
		/* If we have just one entry the second will be empty, we don't fill it */
		bpf_probe_read_user((void *)sops, bpf_core_type_size(struct sembuf), (void *)sops_pointer);
	}
	else
	{
		/* If `nsops>1` we read just the first 2 entries. */
		bpf_probe_read_user((void *)sops, bpf_core_type_size(struct sembuf) * 2, (void *)sops_pointer);
	}

	/* Parameter 3: sem_num_0 (type: PT_UINT16) */
	ringbuf__store_u16(&ringbuf, sops[0].sem_num);

	/* Parameter 4: sem_op_0 (type: PT_INT16) */
	ringbuf__store_s16(&ringbuf, sops[0].sem_op);

	/* Parameter 5: sem_flg_0 (type: PT_FLAGS16) */
	ringbuf__store_u16(&ringbuf, semop_flags_to_scap(sops[0].sem_flg));

	/* Parameter 6: sem_num_1 (type: PT_UINT16) */
	ringbuf__store_u16(&ringbuf, sops[1].sem_num);

	/* Parameter 7: sem_op_1 (type: PT_INT16) */
	ringbuf__store_s16(&ringbuf, sops[1].sem_op);

	/* Parameter 8: sem_flg_1 (type: PT_FLAGS16) */
	ringbuf__store_u16(&ringbuf, semop_flags_to_scap(sops[1].sem_flg));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
