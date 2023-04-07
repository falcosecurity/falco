/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

/* These BPF programs are used both for `pipe` and `pipe2` syscalls. */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(pipe_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, PIPE_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_PIPE_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameters to collect.

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(pipe_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, PIPE_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_PIPE_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	s32 pipefd[2] = {-1, -1};
	/* This is a pointer to the vector with the 2 file descriptors. */
	unsigned long fd_vector_pointer = extract__syscall_argument(regs, 0);
	if(bpf_probe_read_user((void *)pipefd, sizeof(pipefd), (void *)fd_vector_pointer) != 0)
	{
		pipefd[0] = -1;
		pipefd[1] = -1;
	}

	/* Parameter 2: fd1 (type: PT_FD) */
	ringbuf__store_s64(&ringbuf, (s64)pipefd[0]);

	/* Parameter 3: fd2 (type: PT_FD) */
	ringbuf__store_s64(&ringbuf, (s64)pipefd[1]);

	u64 ino = 0;
	/* On success, pipe returns `0` */
	if(ret == 0)
	{
		extract__ino_from_fd(pipefd[0], &ino);
	}

	/* Parameter 4: ino (type: PT_UINT64) */
	ringbuf__store_u64(&ringbuf, ino);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
