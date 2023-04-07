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
int BPF_PROG(symlinkat_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SYMLINKAT_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SYMLINKAT_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameters to collect.

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(symlinkat_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_SYMLINKAT_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: target (type: PT_CHARBUF) */
	unsigned long target_pointer = extract__syscall_argument(regs, 0);
	auxmap__store_charbuf_param(auxmap, target_pointer, MAX_PATH, USER);

	/* Parameter 3: linkdirfd (type: PT_FD) */
	s32 linkdirfd = (s32)extract__syscall_argument(regs, 1);
	if(linkdirfd == AT_FDCWD)
	{
		linkdirfd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, (s64)linkdirfd);

	/* Parameter 4: linkpath (type: PT_FSRELPATH) */
	unsigned long linkpath_pointer = extract__syscall_argument(regs, 2);
	auxmap__store_charbuf_param(auxmap, linkpath_pointer, MAX_PATH, USER);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
