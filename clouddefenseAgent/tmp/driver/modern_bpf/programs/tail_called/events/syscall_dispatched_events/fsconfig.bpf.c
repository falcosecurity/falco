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
int BPF_PROG(fsconfig_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, FSCONFIG_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_FSCONFIG_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameters to collect.

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(fsconfig_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_FSCONFIG_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: ret (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: fd (type: PT_FD) */
	/* This is the file-system fd */
	s32 fd = (s32)extract__syscall_argument(regs, 0);
	auxmap__store_s64_param(auxmap, (s64)fd);

	/* Parameter 3: cmd (type: PT_ENUMFLAGS32) */
	u32 cmd = (u32)extract__syscall_argument(regs, 1);
	u32 scap_cmd = fsconfig_cmds_to_scap(cmd);
	auxmap__store_u32_param(auxmap, scap_cmd);

	/* Parameter 4: key (type: PT_CHARBUF) */
	unsigned long key_pointer = extract__syscall_argument(regs, 2);
	auxmap__store_charbuf_param(auxmap, key_pointer, MAX_PARAM_SIZE, USER);

	int aux = extract__syscall_argument(regs, 4);

	if(ret < 0)
	{
		/* If the syscall fails we push empty params to userspace. */

		/* Parameter 5: value_bytebuf (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);

		/* Parameter 6: value_charbuf (type: PT_CHARBUF) */
		auxmap__store_empty_param(auxmap);
	}
	else
	{
		unsigned long value_pointer = extract__syscall_argument(regs, 3);

		/* According to the command we need to understand what value we have to push to userspace. */
		/* see https://elixir.bootlin.com/linux/latest/source/fs/fsopen.c#L271 */
		switch(scap_cmd)
		{
		case PPM_FSCONFIG_SET_FLAG:
		case PPM_FSCONFIG_SET_FD:
		case PPM_FSCONFIG_CMD_CREATE:
		case PPM_FSCONFIG_CMD_RECONFIGURE:
			/* Since `value` is NULL we send two empty params. */

			/* Parameter 5: value_bytebuf (type: PT_BYTEBUF) */
			auxmap__store_empty_param(auxmap);

			/* Parameter 6: value_charbuf (type: PT_CHARBUF) */
			auxmap__store_empty_param(auxmap);
			break;

		case PPM_FSCONFIG_SET_STRING:
		case PPM_FSCONFIG_SET_PATH:
		case PPM_FSCONFIG_SET_PATH_EMPTY:
			/* `value` is a NUL-terminated string.
			 * Push `value_charbuf` but not `value_bytebuf` (empty).
			 */

			/* Parameter 5: value_bytebuf (type: PT_BYTEBUF) */
			auxmap__store_empty_param(auxmap);

			/* Parameter 6: value_charbuf (type: PT_CHARBUF) */
			auxmap__store_charbuf_param(auxmap, value_pointer, MAX_PATH, USER);
			break;

		case PPM_FSCONFIG_SET_BINARY:
			/* `value` points to a binary blob and `aux` indicates its size.
			 * Push `value_bytebuf` but not `value_charbuf` (empty).
			 */

			/* Parameter 5: value_bytebuf (type: PT_BYTEBUF) */
			auxmap__store_bytebuf_param(auxmap, value_pointer, aux, USER);

			/* Parameter 6: value_charbuf (type: PT_CHARBUF) */
			auxmap__store_empty_param(auxmap);
			break;

		default:
			/* Parameter 5: value_bytebuf (type: PT_BYTEBUF) */
			auxmap__store_empty_param(auxmap);

			/* Parameter 6: value_charbuf (type: PT_CHARBUF) */
			auxmap__store_empty_param(auxmap);
			break;
		}
	}

	/* Parameter 7: aux (type: PT_INT32) */
	auxmap__store_s32_param(auxmap, aux);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
