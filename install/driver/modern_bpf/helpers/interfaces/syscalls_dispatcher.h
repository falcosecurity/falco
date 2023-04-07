/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

/* Syscall dispatcher programs are always attached programs. */
#include <helpers/base/maps_getters.h>
#include <helpers/base/read_from_task.h>
#include <helpers/extract/extract_from_kernel.h>

static __always_inline bool syscalls_dispatcher__check_32bit_syscalls()
{
	uint32_t status;
	struct task_struct *task = get_current_task();

#if defined(__TARGET_ARCH_x86)
	READ_TASK_FIELD_INTO(&status, task, thread_info.status);
	return status & TS_COMPAT;
#elif defined(__TARGET_ARCH_arm64)
	READ_TASK_FIELD_INTO(&status, task, thread_info.flags);
	return status & _TIF_32BIT;
#elif defined(__TARGET_ARCH_s390)
	READ_TASK_FIELD_INTO(&status, task, thread_info.flags);
	return status & _TIF_31BIT;
#else
	return false;
#endif
}

static __always_inline bool syscalls_dispatcher__64bit_interesting_syscall(u32 syscall_id)
{
	return maps__64bit_interesting_syscall(syscall_id);
}

static __always_inline long convert_network_syscalls(struct pt_regs *regs)
{
	int socketcall_id = (int)extract__syscall_argument(regs, 0);

	switch(socketcall_id)
	{
#ifdef __NR_socket
	case SYS_SOCKET:
		return __NR_socket;
#endif

#ifdef __NR_socketpair
	case SYS_SOCKETPAIR:
		return __NR_socketpair;
#endif

	case SYS_ACCEPT:
#if defined(__TARGET_ARCH_s390) && defined(__NR_accept4)
		return __NR_accept4;
#elif defined(__NR_accept)
		return __NR_accept;
#endif
		break;

#ifdef __NR_accept4
	case SYS_ACCEPT4:
		return __NR_accept4;
#endif

#ifdef __NR_bind
	case SYS_BIND:
		return __NR_bind;
#endif

#ifdef __NR_listen
	case SYS_LISTEN:
		return __NR_listen;
#endif

#ifdef __NR_connect
	case SYS_CONNECT:
		return __NR_connect;
#endif

#ifdef __NR_getsockname
	case SYS_GETSOCKNAME:
		return __NR_getsockname;
#endif

#ifdef __NR_getpeername
	case SYS_GETPEERNAME:
		return __NR_getpeername;
#endif

#ifdef __NR_getsockopt
	case SYS_GETSOCKOPT:
		return __NR_getsockopt;
#endif

#ifdef __NR_setsockopt
	case SYS_SETSOCKOPT:
		return __NR_setsockopt;
#endif

#ifdef __NR_recv
	case SYS_RECV:
		return __NR_recv;
#endif

#ifdef __NR_recvfrom
	case SYS_RECVFROM:
		return __NR_recvfrom;
#endif

#ifdef __NR_recvmsg
	case SYS_RECVMSG:
		return __NR_recvmsg;
#endif

#ifdef __NR_recvmmsg
	case SYS_RECVMMSG:
		return __NR_recvmmsg;
#endif

#ifdef __NR_send
	case SYS_SEND:
		return __NR_send;
#endif

#ifdef __NR_sendto
	case SYS_SENDTO:
		return __NR_sendto;
#endif

#ifdef __NR_sendmsg
	case SYS_SENDMSG:
		return __NR_sendmsg;
#endif

#ifdef __NR_sendmmsg
	case SYS_SENDMMSG:
		return __NR_sendmmsg;
#endif

#ifdef __NR_shutdown
	case SYS_SHUTDOWN:
		return __NR_shutdown;
#endif
	default:
		break;
	}

	return 0;
}
