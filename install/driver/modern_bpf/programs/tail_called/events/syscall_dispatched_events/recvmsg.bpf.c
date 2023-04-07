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
int BPF_PROG(recvmsg_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, RECVMSG_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SOCKET_RECVMSG_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[1];
	extract__network_args(args, 1, regs);

	/* Parameter 1: fd (type: PT_FD)*/
	s32 fd = (s32)args[0];
	ringbuf__store_s64(&ringbuf, (s64)fd);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(recvmsg_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_RECVMSG_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Please note: when the peer has performed an orderly shutdown the return value is 0
	 * and we cannot catch the right length of the data received from the return value.
	 * Right now in this case we send an empty parameter to userspace.
	 */
	if(ret > 0)
	{

		/* Parameter 2: size (type: PT_UINT32) */
		auxmap__store_u32_param(auxmap, (u32)ret);

		/* We read the minimum between `snaplen` and what we really
		 * have in the buffer.
		 */
		unsigned long bytes_to_read = maps__get_snaplen();

		if(bytes_to_read > ret)
		{
			bytes_to_read = ret;
		}

		/* Collect parameters at the beginning to manage socketcalls */
		unsigned long args[2];
		extract__network_args(args, 2, regs);

		/* Parameter 3: data (type: PT_BYTEBUF) */
		unsigned long msghdr_pointer = args[1];
		auxmap__store_msghdr_iovec_data_param(auxmap, msghdr_pointer, bytes_to_read);
		
		/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
		u32 socket_fd = (u32)args[0];
		auxmap__store_socktuple_param(auxmap, socket_fd, INBOUND);
	}
	else
	{
		/* Parameter 2: size (type: PT_UINT32) */
		auxmap__store_u32_param(auxmap, 0);

		/* Parameter 3: data (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);

		/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
		auxmap__store_empty_param(auxmap);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
