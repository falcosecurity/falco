/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(openat_e,
	     struct pt_regs *regs,
	     long id)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_OPENAT_2_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: dirfd (type: PT_FD) */
	s32 dirfd = (s32)extract__syscall_argument(regs, 0);
	if(dirfd == AT_FDCWD)
	{
		dirfd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, (s64)dirfd);

	/* Parameter 2: name (type: PT_FSRELPATH) */
	unsigned long path_pointer = extract__syscall_argument(regs, 1);
	auxmap__store_charbuf_param(auxmap, path_pointer, MAX_PATH, USER);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	u32 flags = (u32)extract__syscall_argument(regs, 2);
	auxmap__store_u32_param(auxmap, open_flags_to_scap(flags));

	/* Parameter 4: mode (type: PT_UINT32) */
	unsigned long mode = extract__syscall_argument(regs, 3);
	auxmap__store_u32_param(auxmap, open_modes_to_scap(flags, mode));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(openat_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_OPENAT_2_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: dirfd (type: PT_FD) */
	s32 dirfd = (s32)extract__syscall_argument(regs, 0);
	if(dirfd == AT_FDCWD)
	{
		dirfd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, (s64)dirfd);

	/* Parameter 3: name (type: PT_FSRELPATH) */
	unsigned long path_pointer = extract__syscall_argument(regs, 1);
	auxmap__store_charbuf_param(auxmap, path_pointer, MAX_PATH, USER);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	u32 flags = (u32)extract__syscall_argument(regs, 2);
	auxmap__store_u32_param(auxmap, open_flags_to_scap(flags));

	/* Parameter 5: mode (type: PT_UINT32) */
	unsigned long mode = extract__syscall_argument(regs, 3);
	auxmap__store_u32_param(auxmap, open_modes_to_scap(flags, mode));

	dev_t dev = 0;
	u64 ino = 0;

	if(ret > 0)
	{
		extract__dev_and_ino_from_fd(ret, &dev, &ino);
	}

	/* Parameter 6: dev (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, dev);

	/* Parameter 7: ino (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
