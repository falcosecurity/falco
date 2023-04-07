/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>
#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(recv_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, RECV_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SOCKET_RECV_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[3];
	extract__network_args(args, 3, regs);

	/* Parameter 1: fd (type: PT_FD) */
	s32 fd = (s32)args[0];
	ringbuf__store_s64(&ringbuf, (s64)fd);

	/* Parameter 2: size (type: PT_UINT32) */
	u32 size = (u32)args[2];
	ringbuf__store_u32(&ringbuf, size);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(recv_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_RECV_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	if(ret > 0)
	{
		/* Collect parameters at the beginning to manage socketcalls */
		unsigned long args[2];
		extract__network_args(args, 2, regs);

		unsigned long bytes_to_read = maps__get_snaplen();
		if(bytes_to_read > ret)
		{
			bytes_to_read = ret;
		}

		/* Parameter 2: data (type: PT_BYTEBUF) */
		unsigned long data_pointer = args[1];
		auxmap__store_bytebuf_param(auxmap, data_pointer, bytes_to_read, USER);
	}
	else
	{
		/* Parameter 2: data (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
