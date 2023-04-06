/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(socketpair_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SOCKETPAIR_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SOCKET_SOCKETPAIR_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[3];
	extract__network_args(args, 3, regs);

	/* Parameter 1: domain (type: PT_ENUMFLAGS32) */
	/* why to send 32 bits if we need only 8 bits? */
	u8 domain = (u8)args[0];
	ringbuf__store_u32(&ringbuf, (u32)socket_family_to_scap(domain));

	/* Parameter 2: type (type: PT_UINT32) */
	/* this should be an int, not a uint32 */
	u32 type = (u32)args[1];
	ringbuf__store_u32(&ringbuf, type);

	/* Parameter 3: proto (type: PT_UINT32) */
	/* this should be an int, not a uint32 */
	u32 proto = (u32)args[2];
	ringbuf__store_u32(&ringbuf, proto);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(socketpair_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SOCKETPAIR_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SOCKET_SOCKETPAIR_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	s32 fds[2] = {-1, -1};
	unsigned long source = 0;
	unsigned long peer = 0;
	unsigned long fds_pointer = 0;

	/* In case of success we have 0. */
	if(ret == 0)
	{
		/* Collect parameters at the beginning to manage socketcalls */
		unsigned long args[4];
		extract__network_args(args, 4, regs);

		/* Get new sockets. */
		fds_pointer = args[3];
		bpf_probe_read_user((void *)fds, 2 * sizeof(s32), (void *)fds_pointer);

		/* Get source and peer. */
		struct file *file = extract__file_struct_from_fd((s32)fds[0]);
		struct socket *socket = BPF_CORE_READ(file, private_data);
		BPF_CORE_READ_INTO(&source, socket, sk);
		struct unix_sock *us = (struct unix_sock *)source;
		BPF_CORE_READ_INTO(&peer, us, peer);
	}

	/* Parameter 2: fd1 (type: PT_FD) */
	ringbuf__store_s64(&ringbuf, (s64)fds[0]);

	/* Parameter 3: fd2 (type: PT_FD) */
	ringbuf__store_s64(&ringbuf, (s64)fds[1]);

	/* Parameter 4: source (type: PT_UINT64) */
	ringbuf__store_u64(&ringbuf, source);

	/* Parameter 5: peer (type: PT_UINT64) */
	ringbuf__store_u64(&ringbuf, peer);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
