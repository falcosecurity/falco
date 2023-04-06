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
int BPF_PROG(mount_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, MOUNT_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_MOUNT_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: flags (type: PT_FLAGS32) */
	u32 flags = (u32)extract__syscall_argument(regs, 3);

	/* The `mountflags` argument may have the magic number 0xC0ED
	 * (MS_MGC_VAL) in the top 16 bits. (All of the other flags
	 * occupy the low order 16 bits of `mountflags`.)
	 * Specifying MS_MGC_VAL was required in kernel
	 * versions prior to 2.4, but since Linux 2.4 is no longer required
	 * and is ignored if specified.
	 */
	/* Check the magic number 0xC0ED in the top 16 bits and ignore it if specified. */
	if((flags & PPM_MS_MGC_MSK) == PPM_MS_MGC_VAL)
	{
		flags &= ~PPM_MS_MGC_MSK;
	}
	ringbuf__store_u32(&ringbuf, flags);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(mount_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_MOUNT_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: dev (type: PT_CHARBUF) */
	unsigned long source_pointer = extract__syscall_argument(regs, 0);
	auxmap__store_charbuf_param(auxmap, source_pointer, MAX_PATH, USER);

	/* Parameter 3: dir (type: PT_FSPATH) */
	unsigned long target_pointer = extract__syscall_argument(regs, 1);
	auxmap__store_charbuf_param(auxmap, target_pointer, MAX_PATH, USER);

	/* Parameter 4: type (type: PT_CHARBUF) */
	unsigned long fstype_pointer = extract__syscall_argument(regs, 2);
	auxmap__store_charbuf_param(auxmap, fstype_pointer, MAX_PARAM_SIZE, USER);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
