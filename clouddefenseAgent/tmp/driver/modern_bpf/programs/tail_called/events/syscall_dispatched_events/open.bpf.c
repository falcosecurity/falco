/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(open_e,
	     struct pt_regs *regs,
	     long id)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_OPEN_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: name (type: PT_FSPATH) */
	unsigned long name_pointer = extract__syscall_argument(regs, 0);
	auxmap__store_charbuf_param(auxmap, name_pointer, MAX_PATH, USER);

	/* Parameter 2: flags (type: PT_FLAGS32) */
	u32 flags = (u32)extract__syscall_argument(regs, 1);
	auxmap__store_u32_param(auxmap, open_flags_to_scap(flags));

	/* Parameter 3: mode (type: PT_UINT32) */
	unsigned long mode = extract__syscall_argument(regs, 2);
	auxmap__store_u32_param(auxmap, open_modes_to_scap(flags, mode));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(open_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_OPEN_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: ret (type: PT_FD) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: name (type: PT_FSPATH) */
	unsigned long name_pointer = extract__syscall_argument(regs, 0);
	auxmap__store_charbuf_param(auxmap, name_pointer, MAX_PATH, USER);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	u32 flags = (u32)extract__syscall_argument(regs, 1);
	auxmap__store_u32_param(auxmap, open_flags_to_scap(flags));

	/* Parameter 4: mode (type: PT_UINT32) */
	unsigned long mode = extract__syscall_argument(regs, 2);
	auxmap__store_u32_param(auxmap, open_modes_to_scap(flags, mode));

	dev_t dev = 0;
	u64 ino = 0;

	if(ret > 0)
	{
		extract__dev_and_ino_from_fd(ret, &dev, &ino);
	}

	/* Parameter 5: dev (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, dev);

	/* Parameter 6: ino (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
