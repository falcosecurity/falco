/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(accept_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ACCEPT_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SOCKET_ACCEPT_5_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameters to collect.

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(accept_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_ACCEPT_5_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	auxmap__store_s64_param(auxmap, ret);

	/* If the syscall `connect` succeeds, it creates a new connected socket
	 * with file descriptor `ret` and we can get some parameters, otherwise we return
	 * default values.
	 */

	/* actual dimension of the server queue. */
	u32 queuelen = 0;

	/* max dimension of the server queue. */
	u32 queuemax = 0;

	/* occupancy percentage of the server queue. */
	u8 queuepct = 0;

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	if(ret >= 0)
	{
		auxmap__store_socktuple_param(auxmap, (s32)ret, INBOUND);

		/* Collect parameters at the beginning to  manage socketcalls */
		unsigned long args[1];
		extract__network_args(args, 1, regs);

		/* Perform some computations to get queue information. */
		/* If the syscall is successful the `sockfd` will be >= 0. We want
		 * to extract information from the listening socket, not from the
		 * new one.
		 */
		s32 sockfd = (s32)args[0];
		struct file *file = NULL;
		file = extract__file_struct_from_fd(sockfd);
		struct socket *socket = BPF_CORE_READ(file, private_data);
		struct sock *sk = BPF_CORE_READ(socket, sk);
		BPF_CORE_READ_INTO(&queuelen, sk, sk_ack_backlog);
		BPF_CORE_READ_INTO(&queuemax, sk, sk_max_ack_backlog);
		if(queuelen && queuemax)
		{
			queuepct = (u8)((u64)queuelen * 100 / queuemax);
		}
	}
	else
	{
		auxmap__store_empty_param(auxmap);
	}

	/* Parameter 3: queuepct (type: PT_UINT8) */
	auxmap__store_u8_param(auxmap, queuepct);

	/* Parameter 4: queuelen (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, queuelen);

	/* Parameter 5: queuemax (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, queuemax);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
