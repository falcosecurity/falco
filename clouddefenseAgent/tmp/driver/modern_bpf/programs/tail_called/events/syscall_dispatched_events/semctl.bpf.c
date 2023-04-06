/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(semctl_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SEMCTL_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SEMCTL_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: semid (type: PT_INT32) */
	s32 semid = (s32)extract__syscall_argument(regs, 0);
	ringbuf__store_s32(&ringbuf, semid);

	/* Parameter 2: semnum (type: PT_INT32) */
	s32 semnum = (s32)extract__syscall_argument(regs, 1);
	ringbuf__store_s32(&ringbuf, semnum);

	/* Parameter 3: cmd (type: PT_FLAGS16) */
	u16 cmd = (u16)extract__syscall_argument(regs, 2);
	ringbuf__store_u16(&ringbuf, semctl_cmd_to_scap(cmd));

	/* Parameter 4: val (type: PT_INT32) */
	s32 val = 0;
	if(cmd == SETVAL)
	{
		val = (s32)extract__syscall_argument(regs, 3);
	}
	ringbuf__store_s32(&ringbuf, val);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(semctl_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SEMCTL_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SEMCTL_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, (s64)ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}