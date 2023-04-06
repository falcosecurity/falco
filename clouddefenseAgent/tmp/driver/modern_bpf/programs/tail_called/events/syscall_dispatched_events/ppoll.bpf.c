/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(ppoll_e,
	     struct pt_regs *regs,
	     long id)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_PPOLL_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Get the `fds_pointer` and the number of `fds` from the syscall arguments */
	unsigned long fds_pointer = extract__syscall_argument(regs, 0);
	u32 nfds = (u32)extract__syscall_argument(regs, 1);

	/* Parameter 1: fds (type: PT_FDLIST) */
	/* We are in the enter event so we get the requested events, the returned events are only available
	 * in the exit event.
	 */
	auxmap__store_fdlist_param(auxmap, fds_pointer, nfds, REQUESTED_EVENTS);

	/* Parameter 2: timeout (type: PT_RELTIME) */
	struct __kernel_timespec ts = {0};
	unsigned long ts_pointer = extract__syscall_argument(regs, 2);
	bpf_probe_read_user(&ts, bpf_core_type_size(struct __kernel_timespec), (void *)ts_pointer);
	auxmap__store_u64_param(auxmap, ((u64)ts.tv_sec) * SECOND_TO_NS + ts.tv_nsec);

	/* Parameter 3: sigmask (type: PT_SIGSET) */
	long unsigned int sigmask[1] = {0};
	unsigned long sigmask_pointer = extract__syscall_argument(regs, 3);
	if(bpf_probe_read_user(&sigmask, sizeof(sigmask), (void *)sigmask_pointer))
	{
		/* In case of invalid pointer, return 0 */
		auxmap__store_u32_param(auxmap, (u32)0);
	}
	else
	{
		auxmap__store_u32_param(auxmap, (u32)sigmask[0]);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(ppoll_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_PPOLL_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: ret (type: PT_FD) */
	auxmap__store_s64_param(auxmap, ret);

	/* Get the `fds_pointer` and the number of `fds` from the syscall arguments */
	unsigned long fds_pointer = extract__syscall_argument(regs, 0);
	u32 nfds = (u32)extract__syscall_argument(regs, 1);

	/* Parameter 2: fds (type: PT_FDLIST) */
	auxmap__store_fdlist_param(auxmap, fds_pointer, nfds, RETURNED_EVENTS);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
