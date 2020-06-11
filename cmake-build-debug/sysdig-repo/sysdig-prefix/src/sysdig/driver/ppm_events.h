/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef EVENTS_H_
#define EVENTS_H_

/* To know about __NR_socketcall */
#include <asm/unistd.h>
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

#ifdef __NR_socketcall
	#define _HAS_SOCKETCALL
#endif
#if defined(CONFIG_X86_64) && defined(CONFIG_IA32_EMULATION)
	#define _HAS_SOCKETCALL
#endif

#include "ppm_events_public.h"

/*
 * Various crap that a callback might need
 */
struct fault_data_t {
	unsigned long address;
	struct pt_regs *regs;
	unsigned long error_code;
};

struct event_filler_arguments {
	struct ppm_consumer_t *consumer;
	char *buffer; /* the buffer that will be filled with the data */
	u32 buffer_size; /* the space in the ring buffer available for this event */
	u32 syscall_id; /* the system call ID */
	const enum ppm_syscall_code *cur_g_syscall_code_routing_table;
#ifdef PPM_ENABLE_SENTINEL
	u32 sentinel;
#endif
	u32 nevents;
	u32 curarg;
	u32 nargs;
	u32 arg_data_offset;
	u32 arg_data_size;
	enum ppm_event_type event_type;	/* the event type */
	/* Eventually convert this to an event_info union and move all the
	 * below per-event params in this union, it's not good to waste kernel
	 * stack since all this stuff is always exclusive
	 */
	struct pt_regs *regs; /* the registers containing the call arguments */
	struct task_struct *sched_prev; /* for context switch events, the task that is being scheduled out */
	struct task_struct *sched_next; /* for context switch events, the task that is being scheduled in */
	char *str_storage; /* String storage. Size is one page. */
	unsigned long socketcall_args[6];
	bool is_socketcall;
	int socketcall_syscall;
	bool compat;
	int fd; /* Passed by some of the fillers to val_to_ring to compute the snaplen dynamically */
	bool enforce_snaplen;
	int signo; /* Signal number */
	__kernel_pid_t spid; /* PID of source process */
	__kernel_pid_t dpid; /* PID of destination process */
	struct fault_data_t fault_data; /* For page faults */
};

extern const struct ppm_event_entry g_ppm_events[];

/*
 * HTTP markers
 */
#define HTTP_GET_STR "GET "
#define HTTP_OPTIONS_STR "OPTI"
#define HTTP_HEAD_STR "HEAD"
#define HTTP_POST_STR "POST"
#define HTTP_PUT_STR "PUT "
#define HTTP_DELETE_STR "DELE"
#define HTTP_TRACE_STR "TRAC"
#define HTTP_CONNECT_STR "CONN"
#define HTTP_RESP_STR "HTTP"

/*
 * Functions
 */
int32_t dpi_lookahead_init(void);
int32_t val_to_ring(struct event_filler_arguments *args, u64 val, u32 val_len, bool fromuser, u8 dyn_idx);
u16 pack_addr(struct sockaddr *usrsockaddr, int ulen, char *targetbuf, u16 targetbufsize);
u16 fd_to_socktuple(int fd, struct sockaddr *usrsockaddr, int ulen, bool use_userdata, bool is_inbound, char *targetbuf, u16 targetbufsize);
int addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr *kaddr);
int32_t parse_readv_writev_bufs(struct event_filler_arguments *args, const struct iovec __user *iovsrc, unsigned long iovcnt, int64_t retval, int flags);

#ifdef CONFIG_COMPAT
int32_t compat_parse_readv_writev_bufs(struct event_filler_arguments *args, const struct compat_iovec __user *iovsrc, unsigned long iovcnt, int64_t retval, int flags);
#endif

static inline int add_sentinel(struct event_filler_arguments *args)
{
#ifdef PPM_ENABLE_SENTINEL
	if (likely(args->arg_data_size >= sizeof(u32))) {
		*(u32 *)(args->buffer + args->arg_data_offset) = args->sentinel;
		args->arg_data_offset += 4;
		args->arg_data_size -= 4;
		return PPM_SUCCESS;
	}
	return PPM_FAILURE_BUFFER_FULL;
#else
	return PPM_SUCCESS;
#endif
}

#endif /* EVENTS_H_ */
