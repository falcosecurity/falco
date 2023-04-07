/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#ifndef UDIG
#include <linux/compat.h>
#include <linux/kobject.h>
#include <linux/cdev.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <net/compat.h>
#include <net/ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/mman.h>
#include <linux/in.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20)
#include <linux/mount.h>
#include "ppm_syscall.h"
#else
#include <asm/syscall.h>
#endif
#else // UDIG
#define _GNU_SOURCE
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/sem.h>
#include <sys/file.h>
#include <sys/quota.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "udig_capture.h"
#include "ppm_ringbuffer.h"
#include "ppm_events_public.h"
#include "ppm_events.h"
#include "ppm.h"

#include "udig_inf.h"
#endif /* UDIG */

#include "ppm_ringbuffer.h"
#include "ppm_events_public.h"
#include "ppm_events.h"
#include "ppm.h"
#include "ppm_flag_helpers.h"
#include "ppm_version.h"

/*
 * The kernel patched with grsecurity makes the default access_ok trigger a
 * might_sleep(), so if present we use the one defined by them
 */
#ifndef UDIG
#ifdef access_ok_noprefault
#define ppm_access_ok access_ok_noprefault
#else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)) || (PPM_RHEL_RELEASE_CODE > 0 && PPM_RHEL_RELEASE_CODE >= PPM_RHEL_RELEASE_VERSION(8, 1))
#define ppm_access_ok(type, addr, size)	access_ok(addr, size)
#else
#define ppm_access_ok(type, addr, size)	access_ok(type, addr, size)
#endif
#endif

extern bool g_tracers_enabled;

static void memory_dump(char *p, size_t size)
{
	unsigned int j;

	for (j = 0; j < size; j += 8)
		pr_info("%*ph\n", 8, &p[j]);
}
#endif // UDIG

static inline bool in_port_range(uint16_t port, uint16_t min, uint16_t max)
{
	return port >= min && port <= max;
}

/*
 * Globals
 */
u32 g_http_options_intval;
u32 g_http_get_intval;
u32 g_http_head_intval;
u32 g_http_post_intval;
u32 g_http_put_intval;
u32 g_http_delete_intval;
u32 g_http_trace_intval;
u32 g_http_connect_intval;
u32 g_http_resp_intval;

#ifndef UDIG
/*
 * What this function does is basically a special memcpy
 * so that, if the page fault handler detects the address is invalid,
 * won't kill the process but will return a positive number
 * Plus, this doesn't sleep.
 * The risk is that if the buffer is partially paged out, we get an error.
 * Returns the number of bytes NOT read.
 */
unsigned long ppm_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	unsigned long res = n;

	pagefault_disable();

	if (likely(ppm_access_ok(VERIFY_READ, from, n)))
		res = __copy_from_user_inatomic(to, from, n);

	pagefault_enable();

	return res;
}

/*
 * On some kernels (e.g. 2.6.39), even with preemption disabled, the strncpy_from_user,
 * instead of returning -1 after a page fault, schedules the process, so we drop events
 * because of the preemption. This function reads the user buffer in atomic chunks, and
 * returns when:
 * 1. there's an error (returns `-1`).
 * 2. the terminator is found. (the `\0` is computed in the overall length)
 * 3. we have read `n` bytes. (in this case, we don't have the `\0` but it's ok we will add it in the caller)
 */
/// TODO: we need to change the return value to `int` and the third param from `unsigned long n` to 'uint32_t n`
long ppm_strncpy_from_user(char *to, const char __user *from, unsigned long n)
{
	long string_length = 0;
	long res = -1;
	unsigned long bytes_to_read = 4;
	int j;

	pagefault_disable();

	while (n) {
		/*
		 * Read bytes_to_read bytes at a time, and look for the terminator. Should be fast
		 * since the copy_from_user is optimized for the processor
		 */
		if (n < bytes_to_read)
			bytes_to_read = n;

		if (!ppm_access_ok(VERIFY_READ, from, bytes_to_read)) {
			res = -1;
			goto strncpy_end;
		}

		if (__copy_from_user_inatomic(to, from, bytes_to_read)) {
			/*
			 * Page fault
			 */
			res = -1;
			goto strncpy_end;
		}

		n -= bytes_to_read;
		from += bytes_to_read;

		for (j = 0; j < bytes_to_read; ++j) {
			++string_length;

			/* Check if `*to` is the `\0`. */
			if (!*to) {
				res = string_length;
				goto strncpy_end;
			}

			++to;
		}
	}
	/* We read all the `n` bytes. */
	res = string_length;

strncpy_end:
	pagefault_enable();
	return res;
}
#endif

int32_t dpi_lookahead_init(void)
{
	g_http_options_intval = (*(u32 *)HTTP_OPTIONS_STR);
	g_http_get_intval = (*(u32 *)HTTP_GET_STR);
	g_http_head_intval = (*(u32 *)HTTP_HEAD_STR);
	g_http_post_intval = (*(u32 *)HTTP_POST_STR);
	g_http_put_intval = (*(u32 *)HTTP_PUT_STR);
	g_http_delete_intval = (*(u32 *)HTTP_DELETE_STR);
	g_http_trace_intval = (*(u32 *)HTTP_TRACE_STR);
	g_http_connect_intval = (*(u32 *)HTTP_CONNECT_STR);
	g_http_resp_intval = (*(u32 *)HTTP_RESP_STR);

	return PPM_SUCCESS;
}

#ifndef UDIG
inline int sock_getname(struct socket* sock, struct sockaddr* sock_address, int peer)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	/*
	 * Avoid calling sock->ops->getname(), because in certain kernel versions,
	 * the getname functions may take a lock, which violates the limitations of
	 * the RCU lock execution environment which is used by the kernel module.
	 *
	 * An example is the usage of `BPF_CGROUP_RUN_SA_PROG_LOCK` since kernel version `5.8.0`
	 * https://elixir.bootlin.com/linux/v5.8/source/net/ipv4/af_inet.c#L785
	 *
	 * For efficiency, only fill in sockaddr fields actually used by the
	 * kernel module logic; in particular, skip filling in
	 * - sin_zero
	 * - sin6_scope_id
	 * - sin6_flowinfo
	 */
	struct sock *sk = sock->sk;

	switch(sk->sk_family) {
	case AF_INET:
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)sock_address;
		struct inet_sock *inet = (struct inet_sock *)sk;

		sin->sin_family = AF_INET;
		if (peer) {
			if (!inet->inet_dport ||
			    ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT))) {
				return -ENOTCONN;
			}
			sin->sin_port = inet->inet_dport;
			sin->sin_addr.s_addr = inet->inet_daddr;
		} else {
			u32 addr = inet->inet_rcv_saddr;
			if (!addr) {
				addr = inet->inet_saddr;
			}
			sin->sin_port = inet->inet_sport;
			sin->sin_addr.s_addr = addr;
		}
		break;
	}
	case AF_INET6:
	{
		struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sock_address;
		struct inet_sock *inet = (struct inet_sock *)sk;
		struct ipv6_pinfo *np = (struct ipv6_pinfo *)inet->pinet6;

		sin->sin6_family = AF_INET6;
		if (peer) {
			if ((!inet->inet_dport) ||
			    ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT))) {
				return -ENOTCONN;
			}
			sin->sin6_port = inet->inet_dport;
			sin->sin6_addr = sk->sk_v6_daddr;
		} else {
			sin->sin6_addr = sk->sk_v6_rcv_saddr;
			if (ipv6_addr_any(&sin->sin6_addr)) {
				sin->sin6_addr = np->saddr;
			}
			sin->sin6_port = inet->inet_sport;
		}
		break;
	}

	case AF_UNIX:
	{
		struct sockaddr_un *sunaddr = (struct sockaddr_un *)sock_address;
		struct unix_sock *u;
		struct unix_address *u_addr = NULL;

		if (peer) {
			sk = ((struct unix_sock *)sk)->peer;
			if (!sk) {
				return -ENOTCONN;
			}
		}

		u = (struct unix_sock *)sk;
		u_addr = u->addr;
		if (!u_addr) {
			sunaddr->sun_family = AF_UNIX;
			sunaddr->sun_path[0] = 0;
		} else {
			unsigned int len = u_addr->len;
			if (unlikely(len > sizeof(struct sockaddr_storage))) {
				len = sizeof(struct sockaddr_storage);
			}
			memcpy(sunaddr, u_addr->name, len);
		}
		break;
	}

	default:
		return -ENOTCONN;
	}

	return 0;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	int ret = sock->ops->getname(sock, sock_address, peer);
	if (ret >= 0)
		ret = 0;
	return ret;
#else
	int sockaddr_len;
	return sock->ops->getname(sock, sock_address, &sockaddr_len, peer);
#endif
}

/**
 * Compute the snaplen for the arguments.
 *
 * The snaplen is the amount of argument data returned along with the event.
 * Normally, the driver performs a dynamic calculation to figure out snaplen
 * per-event. However, if this calculation is disabled
 * (i.e. args->consumer->do_dynamic_snaplen == false), the snaplen will always
 * be args->consumer->snaplen.
 *
 * If dynamic snaplen is enabled, here's how the calculation works:
 *
 * 1. If the event is a write to /dev/null, it gets a special snaplen because
 *    writes to /dev/null is a backdoor method for inserting special events
 *    into the event stream.
 * 2. If the event is NOT a socket operation, return args->consumer->snaplen.
 * 3. If the sending port OR destination port falls within the fullcapture port
 *    range specified by the user, return 16000.
 * 4. Protocol detection. A number of applications are detected heuristically
 *    and given a longer snaplen (2000). These applications are MYSQL, Postgres,
 *    HTTP, mongodb, and statsd.
 * 5. If none of the above apply, return args->consumer->snaplen.
 */
inline u32 compute_snaplen(struct event_filler_arguments *args, char *buf, u32 lookahead_size)
{
	u32 res = args->consumer->snaplen;
	int err;
	struct socket *sock;
	sa_family_t family;
	struct sockaddr_storage sock_address;
	struct sockaddr_storage peer_address;
	u16 sport, dport;
	u16 min_port = 0, max_port = 0;
	u32 dynamic_snaplen = 2000;

	if (args->consumer->snaplen > dynamic_snaplen) {
		/*
		 * If the user requested a default snaplen greater than the custom
		 * snaplen given to certain applications, just use the greater value.
		 */
		dynamic_snaplen = args->consumer->snaplen;
	}

	/* Increase snaplen on writes to /dev/null */
	if (g_tracers_enabled && args->event_type == PPME_SYSCALL_WRITE_X) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
		struct fd f = fdget(args->fd);

		if (f.file && f.file->f_inode) {
			if (f.file->f_inode->i_rdev == PPM_NULL_RDEV) {
				res = RW_SNAPLEN_EVENT;
				fdput(f);
				return res;
			}

			fdput(f);
		}
#else
		struct file* file = fget(args->fd);
		/* Use cached f_inode only on kernel versions that have it
		 * https://github.com/torvalds/linux/commit/dd37978c50bc8b354e5c4633f69387f16572fdac
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
		if (file && file->f_inode) {
			if (file->f_inode->i_rdev == PPM_NULL_RDEV) {
		// Use f_dentry for older kernel versions
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,20)
		if (file && file->f_dentry && file->f_dentry->d_inode) {
			if (file->f_dentry->d_inode->i_rdev == PPM_NULL_RDEV) {
#else
		if (file && file->f_path.dentry && file->f_path.dentry->d_inode) {
			if (file->f_path.dentry->d_inode->i_rdev == PPM_NULL_RDEV) {
#endif
				res = RW_SNAPLEN_EVENT;
				fput(file);
				return res;
			}

			fput(file);
		}
#endif
	}

	if (!args->consumer->do_dynamic_snaplen)
		return res;

	sock = sockfd_lookup(args->fd, &err);

	if (!sock) {
		return res;
	}

	if (!sock->sk) {
		goto done;
	}

	err = sock_getname(sock, (struct sockaddr *)&sock_address, 0);

	if (err != 0) {
		goto done;
	}

	/* Try to get the source and destination port */
	if (args->event_type == PPME_SOCKET_SENDTO_X) {
		unsigned long syscall_args[6] = {};
		unsigned long val;
		struct sockaddr __user * usrsockaddr;
		/*
		 * Get the address
		 */
		if (!args->is_socketcall) {
			ppm_syscall_get_arguments(current, args->regs, syscall_args);
			val = syscall_args[4];
		} else {
			val = args->socketcall_args[4];
		}

		usrsockaddr = (struct sockaddr __user *)val;

		if(usrsockaddr == NULL) {
			/*
			 * Suppose is a connected socket, fall back to fd
			 */
			err = sock_getname(sock, (struct sockaddr *)&peer_address, 1);
		} else {
			/*
			 * Get the address len
			 */
			if (!args->is_socketcall) {
				ppm_syscall_get_arguments(current, args->regs, syscall_args);
				val = syscall_args[5];
			} else {
				val = args->socketcall_args[5];
			}

			if (val != 0) {
				/*
				 * Copy the address
				 */
				err = addr_to_kernel(usrsockaddr, val, (struct sockaddr *)&peer_address);
			} else {
				/*
				 * This case should be very rare, fallback again to sock
				 */
				err = sock_getname(sock, (struct sockaddr *)&peer_address, 1);
			}
		}
	} else if (args->event_type == PPME_SOCKET_SENDMSG_X) {
		unsigned long syscall_args[6] = {};
		unsigned long val;
		struct sockaddr __user * usrsockaddr;
		int addrlen;
#ifdef CONFIG_COMPAT
		struct compat_msghdr compat_mh;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
		struct user_msghdr mh;
#else
		struct msghdr mh;
#endif

		if (!args->is_socketcall) {
			ppm_syscall_get_arguments(current, args->regs, syscall_args);
			val = syscall_args[1];
		} else {
			val = args->socketcall_args[1];
		}

#ifdef CONFIG_COMPAT
		if (!args->compat) {
#endif
			if (unlikely(ppm_copy_from_user(&mh, (const void __user *)val, sizeof(mh)))) {
				usrsockaddr = NULL;
				addrlen = 0;
			} else {
				usrsockaddr = (struct sockaddr __user *)mh.msg_name;
				addrlen = mh.msg_namelen;
			}
#ifdef CONFIG_COMPAT
		} else {
			if (unlikely(ppm_copy_from_user(&compat_mh, (const void __user *)compat_ptr(val), sizeof(compat_mh)))) {
				usrsockaddr = NULL;
				addrlen = 0;
			} else {
				usrsockaddr = (struct sockaddr __user *)compat_ptr(compat_mh.msg_name);
				addrlen = compat_mh.msg_namelen;
			}
		}
#endif

		if (usrsockaddr != NULL && addrlen != 0) {
			/*
			 * Copy the address
			 */
			err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&peer_address);
		} else {
			/*
			 * Suppose it is a connected socket, fall back to fd
			 */
			err = sock_getname(sock, (struct sockaddr *)&peer_address, 1);
		}
	} else {
		err = sock_getname(sock, (struct sockaddr *)&peer_address, 1);
	}

	if (err != 0) {
		goto done;
	}

	/*
	 * If there's a valid source / dest port, use it to run heuristics
	 * for determining snaplen.
	 */
	min_port = args->consumer->fullcapture_port_range_start;
	max_port = args->consumer->fullcapture_port_range_end;
	family = sock->sk->sk_family;

	if (family == AF_INET) {
		sport = ntohs(((struct sockaddr_in *) &sock_address)->sin_port);
		dport = ntohs(((struct sockaddr_in *) &peer_address)->sin_port);
	} else if (family == AF_INET6) {
		sport = ntohs(((struct sockaddr_in6 *) &sock_address)->sin6_port);
		dport = ntohs(((struct sockaddr_in6 *) &peer_address)->sin6_port);
	} else {
		sport = 0;
		dport = 0;
	}

	if (max_port > 0 &&
	    (in_port_range(sport, min_port, max_port) ||
	     in_port_range(dport, min_port, max_port))) {
		/*
		 * Before checking the well-known ports, see if the user has requested
		 * an increased snaplen for the port in question.
		 */
		sockfd_put(sock);
		return RW_MAX_FULLCAPTURE_PORT_SNAPLEN;
	} else if (sport == PPM_PORT_MYSQL || dport == PPM_PORT_MYSQL) {
		if (lookahead_size >= 5) {
			if (buf[0] == 3 || buf[1] == 3 || buf[2] == 3 || buf[3] == 3 || buf[4] == 3) {
				res = dynamic_snaplen;
				goto done;
			} else if (buf[2] == 0 && buf[3] == 0) {
				res = dynamic_snaplen;
				goto done;
			}
		}
	} else if (sport == PPM_PORT_POSTGRES || dport == PPM_PORT_POSTGRES) {
		if (lookahead_size >= 2) {
			if ((buf[0] == 'Q' && buf[1] == 0) || /* SimpleQuery command */
			    (buf[0] == 'P' && buf[1] == 0) || /* Prepare statement command */
			    (buf[0] == 'E' && buf[1] == 0) /* error or execute command */
			) {
				res = dynamic_snaplen;
				goto done;
			}
		}
		if (lookahead_size >= 7 &&
		    (buf[4] == 0 && buf[5] == 3 && buf[6] == 0)) { /* startup command */
			res = dynamic_snaplen;
			goto done;
		}
	} else if ((sport == PPM_PORT_MONGODB || dport == PPM_PORT_MONGODB) ||
	            (lookahead_size >= 16 &&
	               (*(int32_t *)(buf+12) == 1    || /* matches header */
	                *(int32_t *)(buf+12) == 2001 ||
	                *(int32_t *)(buf+12) == 2002 ||
	                *(int32_t *)(buf+12) == 2003 ||
	                *(int32_t *)(buf+12) == 2004 ||
	                *(int32_t *)(buf+12) == 2005 ||
	                *(int32_t *)(buf+12) == 2006 ||
	                *(int32_t *)(buf+12) == 2007)
	            )
	          ) {
		res = dynamic_snaplen;
		goto done;
	} else if (dport == args->consumer->statsd_port) {
		res = dynamic_snaplen;
		goto done;
	} else {
		if (lookahead_size >= 5) {
			if (*(u32 *)buf == g_http_get_intval ||
			    *(u32 *)buf == g_http_post_intval ||
			    *(u32 *)buf == g_http_put_intval ||
			    *(u32 *)buf == g_http_delete_intval ||
			    *(u32 *)buf == g_http_trace_intval ||
			    *(u32 *)buf == g_http_connect_intval ||
			    *(u32 *)buf == g_http_options_intval ||
			    ((*(u32 *)buf == g_http_resp_intval) && (buf[4] == '/'))
			) {
				res = dynamic_snaplen;
				goto done;
			}
		}
	}

done:
	sockfd_put(sock);
	return res;
}
#endif // UDIG

int push_empty_param(struct event_filler_arguments *args)
{
	u16 *psize = (u16 *)(args->buffer + args->curarg * sizeof(u16));

	if (unlikely(args->curarg >= args->nargs))
	{
#ifndef UDIG
		pr_err("(%u)val_to_ring: too many arguments for event #%u, type=%u, curarg=%u, nargs=%u tid:%u\n",
			smp_processor_id(),
			args->nevents,
			(u32)args->event_type,
			args->curarg,
			args->nargs,
			current->pid);
		memory_dump(args->buffer - sizeof(struct ppm_evt_hdr), 32);
#endif
		ASSERT(0);
		return PPM_FAILURE_BUG;
	}

	/* We push 0 in the length array */
	*psize = 0;

	/* We increment the current argument */
	args->curarg++;
	return PPM_SUCCESS;
}

/*
 * NOTES:
 * - val_len is ignored for everything other than PT_BYTEBUF.
 * - fromuser is ignored for numeric types
 * - dyn_idx is ignored for everything other than PT_DYN
 */
int val_to_ring(struct event_filler_arguments *args, uint64_t val, u32 val_len, bool fromuser, u8 dyn_idx)
{
	const struct ppm_param_info *param_info;
	int len = -1;
	u16 *psize = (u16 *)(args->buffer + args->curarg * sizeof(u16));
	u32 max_arg_size = args->arg_data_size;

	if (unlikely(args->curarg >= args->nargs)) {
#ifndef UDIG
		pr_err("(%u)val_to_ring: too many arguments for event #%u, type=%u, curarg=%u, nargs=%u tid:%u\n",
			smp_processor_id(),
			args->nevents,
			(u32)args->event_type,
			args->curarg,
			args->nargs,
			current->pid);
		memory_dump(args->buffer - sizeof(struct ppm_evt_hdr), 32);
#endif		
		ASSERT(0);
		return PPM_FAILURE_BUG;
	}

	if (unlikely(args->arg_data_size == 0))
		return PPM_FAILURE_BUFFER_FULL;

	if (max_arg_size > PPM_MAX_ARG_SIZE)
		max_arg_size = PPM_MAX_ARG_SIZE;

	param_info = &(g_event_info[args->event_type].params[args->curarg]);
	if (param_info->type == PT_DYN && param_info->info != NULL) {
		const struct ppm_param_info *dyn_params;

		if (unlikely(dyn_idx >= param_info->ninfo)) {
			ASSERT(0);
			return PPM_FAILURE_BUG;
		}

#if defined(UDIG)
		dyn_params = (const struct ppm_param_info *)patch_pointer((uint8_t*)param_info->info);
#else
		dyn_params = (const struct ppm_param_info *)param_info->info;
#endif

		param_info = &dyn_params[dyn_idx];
		if (likely(max_arg_size >= sizeof(u8)))	{
			*(u8 *)(args->buffer + args->arg_data_offset) = dyn_idx;
			len = sizeof(u8);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}
		args->arg_data_offset += len;
		args->arg_data_size -= len;
		max_arg_size -= len;
		*psize = (u16)len;
	} else {
		*psize = 0;
	}

	switch (param_info->type) {
	case PT_CHARBUF:
	case PT_FSPATH:
	case PT_FSRELPATH:
		if(unlikely(val == 0))
		{
			/* Send an empty param when we have a null pointer `val==0` */
			len = 0;
			break;
		}


		if(fromuser)
		{
			len = ppm_strncpy_from_user(args->buffer + args->arg_data_offset,
				(const char __user *)(syscall_arg_t)val, max_arg_size);

			if(unlikely(len < 0))
			{
				len = 0;
				break;
			}
			/* Two possible cases here:
			 *
			 * 1. `len < max_arg_size`, the terminator is always there, and `len` takes it into account,
			 *    so we need to do nothing. We just push a `\0` to an empty byte to avoid an if
			 *    case.
			 *
			 * 2. `len == max_arg_size`, the terminator is not there but we cannot push an additional
			 *    char for this reason we overwrite the last char and we don't increment `len`.
			 */
			*(char *)(args->buffer + args->arg_data_offset + max_arg_size - 1) = '\0';
		}
		else
		{
			len = (int)strlcpy(args->buffer + args->arg_data_offset,
							(const char *)(syscall_arg_t)val,
							max_arg_size);
			/* WARNING: `strlcpy` returns the length of the string it tries to create
			 * so `len` could also be greater than `max_arg_size`, but please note that the copied
			 * charbuf is at max `max_arg_size` (where the last byte is used for the `\0`).
			 * The copied string is always `\0` terminated but the returned `len` doesn't
			 * take into consideration the `\0` like `strlen()` function.
			 *
			 * Two possible cases here:
			 *
			 * 1. `len < max_arg_size`, the terminator is always there, but `len` doesn't take it into account,
			 *    so we need to increment the `len`. Note that if the source string has exactly `max_arg_size`
			 *    characters the returned `len` is `max_arg_size-1` so we need to do `len++` to obtain the copied size.
			 *
			 * 2. `len >= max_arg_size`, the source string is greater than `max_arg_size`. `strlcpy` copied
			 *    `max_arg_size - 1` and added the `\0` at the end, so our final copied `len` is `max_arg_size` we have just
			 *    to resize it and we have done.
			 */
			if(++len >= max_arg_size)
			{
				len = max_arg_size;
			}
		}
		break;

	case PT_BYTEBUF:
		if (likely(val != 0 && val_len)) {
			if (fromuser)
			{
				/*
				 * Copy the lookahead portion of the buffer that we will use DPI-based
				 * snaplen calculation
				 */
				u32 dpi_lookahead_size = DPI_LOOKAHEAD_SIZE;

				if (dpi_lookahead_size > val_len)
					dpi_lookahead_size = val_len;

				if (unlikely(dpi_lookahead_size >= max_arg_size))
					return PPM_FAILURE_BUFFER_FULL;

				/* Returns the number of bytes NOT read. */
				len = (int)ppm_copy_from_user(args->buffer + args->arg_data_offset,
						(const void __user *)(syscall_arg_t)val,
						dpi_lookahead_size);

				if(unlikely(len != 0))
				{
					goto send_empty_bytebuf_param;
				}

				/*
				 * Check if there's more to copy
				 */
				if (likely((dpi_lookahead_size != val_len))) {
					/*
					 * Calculate the snaplen
					 */
					if (likely(args->enforce_snaplen)) {
						u32 sl = args->consumer->snaplen;

#ifndef UDIG
						sl = compute_snaplen(args, args->buffer + args->arg_data_offset, dpi_lookahead_size);
#endif
						if (val_len > sl)
							val_len = sl;
					}

					if (unlikely((val_len) >= max_arg_size))
						val_len = max_arg_size;

					if (val_len > dpi_lookahead_size) {
						len = (int)ppm_copy_from_user(args->buffer + args->arg_data_offset + dpi_lookahead_size,
								(const uint8_t __user *)(syscall_arg_t)val + dpi_lookahead_size,
								val_len - dpi_lookahead_size);

						if (unlikely(len != 0))
						{
							goto send_empty_bytebuf_param;
						}
					}
				}

				len = val_len;
			}
			else
			{
				if (likely(args->enforce_snaplen)) {
#ifdef UDIG
					u32 sl = args->consumer->snaplen;
#else
					u32 sl = compute_snaplen(args, (char *)(syscall_arg_t)val, val_len);
#endif
					if (val_len > sl)
						val_len = sl;
				}

				if (unlikely(val_len >= max_arg_size))
					return PPM_FAILURE_BUFFER_FULL;

				memcpy(args->buffer + args->arg_data_offset,
					(void *)(syscall_arg_t)val, val_len);

				len = val_len;
			}
			/* If we arrive here we have something to send. */
			break;
		}
		/* Send an empty param in all these cases:
		 * - we have a null pointer `val==0` or `val_len==0`.
		 * - we have read `0` bytes.
		 * - we faced an error while reading.
		 */
send_empty_bytebuf_param:
		len = 0;
		break;

	case PT_SOCKADDR:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
		if(likely(val != 0))
		{
			if (unlikely(val_len >= max_arg_size))
				return PPM_FAILURE_BUFFER_FULL;

			if(fromuser)
			{
				len = (int)ppm_copy_from_user(args->buffer + args->arg_data_offset,
						(const void __user *)(syscall_arg_t)val,
						val_len);

				if(unlikely(len != 0))
				{
					goto send_empty_sock_param;
				}

				len = val_len;
			}
			else
			{
				memcpy(args->buffer + args->arg_data_offset,
					(void *)(syscall_arg_t)val, val_len);

				len = val_len;
			}
			/* If we arrive here we have something to send. */
			break;
		}

send_empty_sock_param:
		len = 0;
		break;

	case PT_FLAGS8:
	case PT_ENUMFLAGS8:
	case PT_UINT8:
	case PT_SIGTYPE:
		if (likely(max_arg_size >= sizeof(u8)))	{
			*(u8 *)(args->buffer + args->arg_data_offset) = (u8)val;
			len = sizeof(u8);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_FLAGS16:
	case PT_ENUMFLAGS16:
	case PT_UINT16:
	case PT_SYSCALLID:
		if (likely(max_arg_size >= sizeof(u16))) {
			*(u16 *)(args->buffer + args->arg_data_offset) = (u16)val;
			len = sizeof(u16);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_FLAGS32:
	case PT_UINT32:
	case PT_MODE:
	case PT_UID:
	case PT_GID:
	case PT_SIGSET:
	case PT_ENUMFLAGS32:
		if (likely(max_arg_size >= sizeof(u32))) {
			*(u32 *)(args->buffer + args->arg_data_offset) = (u32)val;
			len = sizeof(u32);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_UINT64:
		if (likely(max_arg_size >= sizeof(u64))) {
			*(u64 *)(args->buffer + args->arg_data_offset) = (u64)val;
			len = sizeof(u64);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT8:
		if (likely(max_arg_size >= sizeof(s8))) {
			*(s8 *)(args->buffer + args->arg_data_offset) = (s8)(long)val;
			len = sizeof(s8);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT16:
		if (likely(max_arg_size >= sizeof(s16))) {
			*(s16 *)(args->buffer + args->arg_data_offset) = (s16)(long)val;
			len = sizeof(s16);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT32:
		if (likely(max_arg_size >= sizeof(s32))) {
			*(s32 *)(args->buffer + args->arg_data_offset) = (s32)(long)val;
			len = sizeof(s32);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT64:
	case PT_ERRNO:
	case PT_FD:
	case PT_PID:
		if (likely(max_arg_size >= sizeof(s64))) {
			*(s64 *)(args->buffer + args->arg_data_offset) = (s64)(long)val;
			len = sizeof(s64);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	default:
		ASSERT(0);
#ifndef UDIG
		pr_err("val_to_ring: invalid argument type %d. Event %u (%s) might have less parameters than what has been declared in nparams\n",
			(int)g_event_info[args->event_type].params[args->curarg].type,
			(u32)args->event_type,
			g_event_info[args->event_type].name);
#endif			
		return PPM_FAILURE_BUG;
	}

	ASSERT(len <= PPM_MAX_ARG_SIZE);
	ASSERT(len <= (int)max_arg_size);

	*psize += (u16)len;
	args->curarg++;
	args->arg_data_offset += len;
	args->arg_data_size -= len;

	return PPM_SUCCESS;
}

/*
static struct socket *ppm_sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
	struct file *file;
	struct socket *sock;

	*err = -EBADF;
	file = fget_light(fd, fput_needed);
	if (file) {
		sock = sock_from_file(file, err);
		if (sock)
			return sock;
		fput_light(file, *fput_needed);
	}
	return NULL;
}
*/

static void unix_socket_path(char *dest, const char *path, size_t size)
{
	if (path[0] == '\0') {
		/*
		 * Extract from: https://man7.org/linux/man-pages/man7/unix.7.html
		 * an abstract socket address is distinguished (from a
		 * pathname socket) by the fact that sun_path[0] is a null byte
		 * ('\0').  The socket's address in this namespace is given by
		 * the additional bytes in sun_path that are covered by the
		 * specified length of the address structure.
		 */
		snprintf(dest,
			 size,
			 "@%s",
			 path + 1);
	} else {
		snprintf(dest,
			size,
			 "%s",
			 path); /* we assume this will be smaller than (targetbufsize - (1 + 8 + 8)) */
	}
}

/*
 * Convert a sockaddr into our address representation and copy it to
 * targetbuf
 */
u16 pack_addr(struct sockaddr *usrsockaddr,
	int ulen,
	char *targetbuf,
	u16 targetbufsize)
{
	u32 ip;
	u16 port;
	sa_family_t family = usrsockaddr->sa_family;
	struct sockaddr_in *usrsockaddr_in;
	struct sockaddr_in6 *usrsockaddr_in6;
	struct sockaddr_un *usrsockaddr_un;
	u16 size;
	char *dest;

	switch (family) {
	case AF_INET:
		/*
		 * Map the user-provided address to a sockaddr_in
		 */
		usrsockaddr_in = (struct sockaddr_in *)usrsockaddr;

		/*
		 * Retrieve the src address
		 */
		ip = usrsockaddr_in->sin_addr.s_addr;
		port = ntohs(usrsockaddr_in->sin_port);

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 4 + 2; /* family + ip + port */

		*targetbuf = socket_family_to_scap((u8)family);
		*(u32 *)(targetbuf + 1) = ip;
		*(u16 *)(targetbuf + 5) = port;

		break;
	case AF_INET6:
		/*
		 * Map the user-provided address to a sockaddr_in
		 */
		usrsockaddr_in6 = (struct sockaddr_in6 *)usrsockaddr;

		/*
		 * Retrieve the src address
		 */
		port = ntohs(usrsockaddr_in6->sin6_port);

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 16 + 2; /* family + ip + port */

		*targetbuf = socket_family_to_scap((u8)family);
		memcpy(targetbuf + 1,
			usrsockaddr_in6->sin6_addr.s6_addr,
			16);
		*(u16 *)(targetbuf + 17) = port;

		break;
	case AF_UNIX:
		/*
		 * Map the user-provided address to a sockaddr_in
		 */
		usrsockaddr_un = (struct sockaddr_un *)usrsockaddr;

		/*
		 * Put a 0 at the end of struct sockaddr_un because
		 * the user might not have considered it in the length
		 */
		if (ulen == sizeof(struct sockaddr_storage))
			*(((char *)usrsockaddr_un) + ulen - 1) = 0;
		else
			*(((char *)usrsockaddr_un) + ulen) = 0;

		/*
		 * Pack the data into the target buffer
		 */
		size = 1;

		*targetbuf = socket_family_to_scap((u8)family);

		dest = targetbuf + 1;
		unix_socket_path(dest, usrsockaddr_un->sun_path, UNIX_PATH_MAX);

		size += (u16)strlen(dest) + 1;

		break;
	default:
		size = 0;
		break;
	}

	return size;
}

/*
 * Convert a connection tuple into our tuple representation and copy it to
 * targetbuf
 */
u16 fd_to_socktuple(int fd,
	struct sockaddr *usrsockaddr,
	int ulen,
	bool use_userdata,
	bool is_inbound,
	char *targetbuf,
	u16 targetbufsize)
{
	int err = 0;
	sa_family_t family;
	u32 sip;
	u32 dip;
	u8 *sip6;
	u8 *dip6;
	u16 sport;
	u16 dport;
	struct sockaddr_in *usrsockaddr_in;
	struct sockaddr_in6 *usrsockaddr_in6;
	u16 size;
	struct sockaddr_storage sock_address;
	struct sockaddr_storage peer_address;
#ifndef UDIG
	struct socket *sock;
	char *dest;
	struct unix_sock *us;
	char *us_name;
	struct sock *speer;
	struct sockaddr_un *usrsockaddr_un;

	/*
	 * Get the socket from the fd
	 * NOTE: sockfd_lookup() locks the socket, so we don't need to worry when we dig in it
	 */
	sock = sockfd_lookup(fd, &err);

	if (unlikely(!sock || !(sock->sk))) {
		/*
		 * This usually happens if the call failed without being able to establish a connection,
		 * i.e. if it didn't return something like SE_EINPROGRESS.
		 */
		if (sock)
			sockfd_put(sock);
		return 0;
	}
#endif

#ifdef UDIG
	socklen_t alen = sizeof(struct sockaddr_storage);
	err = udig_getsockname(fd, (struct sockaddr *)&sock_address, &alen);
	if(err < 0)
	{
		return 0;
	}

	family = sock_address.ss_family;
#else
	err = sock_getname(sock, (struct sockaddr *)&sock_address, 0);
	ASSERT(err == 0);

	family = sock->sk->sk_family;
#endif

	/*
	 * Extract and pack the info, based on the family
	 */
	switch (family) {
	case AF_INET:
		if (!use_userdata) {
#ifdef UDIG
			socklen_t palen = sizeof(struct sockaddr_storage);
			err = udig_getpeername(fd, (struct sockaddr *)&peer_address, &palen);
#else
			err = sock_getname(sock, (struct sockaddr *)&peer_address, 1);
#endif
			if (err == 0) {
				if (is_inbound) {
					sip = ((struct sockaddr_in *) &peer_address)->sin_addr.s_addr;
					sport = ntohs(((struct sockaddr_in *) &peer_address)->sin_port);
					dip = ((struct sockaddr_in *) &sock_address)->sin_addr.s_addr;
					dport = ntohs(((struct sockaddr_in *) &sock_address)->sin_port);
				} else {
					sip = ((struct sockaddr_in *) &sock_address)->sin_addr.s_addr;
					sport = ntohs(((struct sockaddr_in *) &sock_address)->sin_port);
					dip = ((struct sockaddr_in *) &peer_address)->sin_addr.s_addr;
					dport = ntohs(((struct sockaddr_in *) &peer_address)->sin_port);
				}
			} else {
				sip = 0;
				sport = 0;
				dip = 0;
				dport = 0;
			}
		} else {
			/*
			 * Map the user-provided address to a sockaddr_in
			 */
			usrsockaddr_in = (struct sockaddr_in *)usrsockaddr;

			if (is_inbound) {
				/* To take inbound info we cannot use the `src_addr` obtained from the syscall
				 * it could be empty!
				 * From kernel 3.13 we can take both ipv4 and ipv6 info from here
				 * https://elixir.bootlin.com/linux/v3.13/source/include/net/sock.h#L164
				 */
				#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
					sip = sock->sk->__sk_common.skc_daddr;
					sport = ntohs(sock->sk->__sk_common.skc_dport);
				#else
					/* this is probably wrong, we need to find an alternative in old kernels */
					sip = ((struct sockaddr_in *) &sock_address)->sin_addr.s_addr;
					sport = ntohs(usrsockaddr_in->sin_port);
				#endif
				dip = ((struct sockaddr_in *) &sock_address)->sin_addr.s_addr;
				dport = ntohs(((struct sockaddr_in *) &sock_address)->sin_port);
			} else {
				sip = ((struct sockaddr_in *) &sock_address)->sin_addr.s_addr;
				sport = ntohs(((struct sockaddr_in *) &sock_address)->sin_port);
				dip = usrsockaddr_in->sin_addr.s_addr;
				dport = ntohs(usrsockaddr_in->sin_port);
			}
		}

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 4 + 4 + 2 + 2; /* family + sip + dip + sport + dport */

		*targetbuf = socket_family_to_scap((u8)family);
		*(u32 *)(targetbuf + 1) = sip;
		*(u16 *)(targetbuf + 5) = sport;
		*(u32 *)(targetbuf + 7) = dip;
		*(u16 *)(targetbuf + 11) = dport;

		break;
	case AF_INET6:
		if (!use_userdata) {
#ifdef UDIG
			socklen_t palen = sizeof(struct sockaddr_storage);
			err = udig_getpeername(fd, (struct sockaddr *)&peer_address, &palen);
#else
			err = sock_getname(sock, (struct sockaddr *)&peer_address, 1);
#endif
			ASSERT(err == 0);

			if (is_inbound) {
				sip6 = ((struct sockaddr_in6 *) &peer_address)->sin6_addr.s6_addr;
				sport = ntohs(((struct sockaddr_in6 *) &peer_address)->sin6_port);
				dip6 = ((struct sockaddr_in6 *) &sock_address)->sin6_addr.s6_addr;
				dport = ntohs(((struct sockaddr_in6 *) &sock_address)->sin6_port);
			} else {
				sip6 = ((struct sockaddr_in6 *) &sock_address)->sin6_addr.s6_addr;
				sport = ntohs(((struct sockaddr_in6 *) &sock_address)->sin6_port);
				dip6 = ((struct sockaddr_in6 *) &peer_address)->sin6_addr.s6_addr;
				dport = ntohs(((struct sockaddr_in6 *) &peer_address)->sin6_port);
			}
		} else {
			/*
			 * Map the user-provided address to a sockaddr_in6
			 */
			usrsockaddr_in6 = (struct sockaddr_in6 *)usrsockaddr;

			if (is_inbound) {
				#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
					sip6 = sock->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8;
					sport = ntohs(sock->sk->__sk_common.skc_dport);
				#else
					/* this is probably wrong, we need to find an alternative in old kernels */
					sip6 = usrsockaddr_in6->sin6_addr.s6_addr;
					sport = ntohs(usrsockaddr_in6->sin6_port);
				#endif
				dip6 = ((struct sockaddr_in6 *) &sock_address)->sin6_addr.s6_addr;
				dport = ntohs(((struct sockaddr_in6 *) &sock_address)->sin6_port);
			} else {
				sip6 = ((struct sockaddr_in6 *) &sock_address)->sin6_addr.s6_addr;
				sport = ntohs(((struct sockaddr_in6 *) &sock_address)->sin6_port);
				dip6 = usrsockaddr_in6->sin6_addr.s6_addr;
				dport = ntohs(usrsockaddr_in6->sin6_port);
			}
		}

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 16 + 16 + 2 + 2; /* family + sip + dip + sport + dport */

		*targetbuf = socket_family_to_scap((u8)family);
		memcpy(targetbuf + 1,
			sip6,
			16);
		*(u16 *)(targetbuf + 17) = sport;
		memcpy(targetbuf + 19,
			dip6,
			16);
		*(u16 *)(targetbuf + 35) = dport;

		break;
	case AF_UNIX:
#ifdef UDIG
		size = 0;
#else
		/*
		 * Retrieve the addresses
		 */
		us = unix_sk(sock->sk);
		speer = us->peer;

		*targetbuf = socket_family_to_scap(family);

		if (is_inbound) {
			*(uint64_t *)(targetbuf + 1) = (uint64_t)(unsigned long)us;
			*(uint64_t *)(targetbuf + 1 + 8) = (uint64_t)(unsigned long)speer;
		} else {
			*(uint64_t *)(targetbuf + 1) = (uint64_t)(unsigned long)speer;
			*(uint64_t *)(targetbuf + 1 + 8) = (uint64_t)(unsigned long)us;
		}

		/*
		 * Pack the data into the target buffer
		 */
		size = 1 + 8 + 8;

		if (!use_userdata) {
			if (is_inbound) {
				us_name = ((struct sockaddr_un *) &sock_address)->sun_path;
			} else {
				err = sock_getname(sock, (struct sockaddr *)&peer_address, 1);
				ASSERT(err == 0);

				us_name = ((struct sockaddr_un *) &peer_address)->sun_path;
			}
		} else {
			/*
			 * Map the user-provided address to a sockaddr_in
			 */
			usrsockaddr_un = (struct sockaddr_un *)usrsockaddr;

			/*
			 * Put a 0 at the end of struct sockaddr_un because
			 * the user might not have considered it in the length
			 */
			if (ulen == sizeof(struct sockaddr_storage))
				*(((char *)usrsockaddr_un) + ulen - 1) = 0;
			else
				*(((char *)usrsockaddr_un) + ulen) = 0;

			if (is_inbound)
				us_name = ((struct sockaddr_un *) &sock_address)->sun_path;
			else
				us_name = usrsockaddr_un->sun_path;
		}

		ASSERT(us_name);

		dest = targetbuf + 1 + 8 + 8;
		unix_socket_path(dest, us_name, UNIX_PATH_MAX);

		size += strlen(dest) + 1;
	#endif /* UDIG */
		break;
	default:
		size = 0;
		break;
	}

#ifndef UDIG
	/*
	 * Digging finished. We can release the fd.
	 */
	sockfd_put(sock);
#endif

	return size;
}

int addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr *kaddr)
{
	if (unlikely(ulen < 0 || ulen > sizeof(struct sockaddr_storage)))
		return -EINVAL;

	if (unlikely(ulen == 0))
		return 0;

	if (unlikely(ppm_copy_from_user(kaddr, uaddr, ulen)))
		return -EFAULT;

	return 0;
}

/*
 * Parses the list of buffers of a xreadv or xwritev call, and pushes the size
 * (and optionally the data) to the ring.
 */
int32_t parse_readv_writev_bufs(struct event_filler_arguments *args, const struct iovec __user *iovsrc, unsigned long iovcnt, int64_t retval, int flags)
{
	int32_t res;
	const struct iovec *iov;
	u64 copylen;
	u32 j;
	u64 size = 0;
	unsigned long bufsize;
	char *targetbuf = args->str_storage;
	u32 targetbuflen = STR_STORAGE_SIZE;
	unsigned long syscall_args[6] = {};
	unsigned long val;
	u32 notcopied_len;
	size_t tocopy_len;

	copylen = iovcnt * sizeof(struct iovec);

	if (unlikely(iovcnt >= 0xffffffff))
		return PPM_FAILURE_BUFFER_FULL;

	if (unlikely(copylen >= STR_STORAGE_SIZE))
		return PPM_FAILURE_BUFFER_FULL;

	if (unlikely(ppm_copy_from_user(args->str_storage, iovsrc, copylen)))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	iov = (const struct iovec *)(args->str_storage);

	targetbuf += copylen;
	targetbuflen -= copylen;

	/*
	 * Size
	 */
	if (flags & PRB_FLAG_PUSH_SIZE) {
		for (j = 0; j < iovcnt; j++)
			size += iov[j].iov_len;

		/*
		 * Size is the total size of the buffers provided by the user. The number of
		 * received bytes can be smaller
		 */
		if ((flags & PRB_FLAG_IS_WRITE) == 0)
			if (size > retval)
				size = retval;

		res = val_to_ring(args, size, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	/*
	 * data
	 */
	if (flags & PRB_FLAG_PUSH_DATA) {
		if (retval > 0 && iovcnt > 0) {
			/*
			 * Retrieve the FD. It will be used for dynamic snaplen calculation.
			 */
			if (!args->is_socketcall) {
				ppm_syscall_get_arguments(current, args->regs, syscall_args);
				val = syscall_args[0];
			}
#ifndef UDIG
			else
				val = args->socketcall_args[0];
#endif
			args->fd = (int)val;

			/*
			 * Merge the buffers
			 */
			bufsize = 0;

			for (j = 0; j < iovcnt; j++) {
				if ((flags & PRB_FLAG_IS_WRITE) == 0) {
					if (bufsize >= retval) {
						ASSERT(bufsize >= retval);

						/*
						 * Copied all the data even if we haven't reached the
						 * end of the buffer.
						 * Copy must stop here.
						 */
						break;
					}

					tocopy_len = min(iov[j].iov_len, (size_t)retval - bufsize);
					tocopy_len = min(tocopy_len, (size_t)targetbuflen - bufsize - 1);
				} else {
					tocopy_len = min(iov[j].iov_len, targetbuflen - bufsize - 1);
				}

				notcopied_len = (int)ppm_copy_from_user(targetbuf + bufsize,
						iov[j].iov_base,
						tocopy_len);

				if (unlikely(notcopied_len != 0)) {
					/*
					 * This means we had a page fault. Skip this event.
					 */
					return PPM_FAILURE_INVALID_USER_MEMORY;
				}

				bufsize += tocopy_len;

				if (tocopy_len != iov[j].iov_len) {
					/*
					 * No space left in the args->str_storage buffer.
					 * Copy must stop here.
					 */
					break;
				}
			}

			args->enforce_snaplen = true;

			res = val_to_ring(args,
				(unsigned long)targetbuf,
				bufsize,
				false,
				0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		} else {
			res = val_to_ring(args, 0, 0, false, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		}
	}

	return PPM_SUCCESS;
}

#ifndef UDIG

#ifdef CONFIG_COMPAT
/*
 * Parses the list of buffers of a xreadv or xwritev call, and pushes the size
 * (and optionally the data) to the ring.
 */
int32_t compat_parse_readv_writev_bufs(struct event_filler_arguments *args, const struct compat_iovec __user *iovsrc, unsigned long iovcnt, int64_t retval, int flags)
{
	int32_t res;
	const struct compat_iovec *iov;
	u64 copylen;
	u32 j;
	u64 size = 0;
	unsigned long bufsize;
	char *targetbuf = args->str_storage;
	u32 targetbuflen = STR_STORAGE_SIZE;
	unsigned long syscall_args[6] = {};
	unsigned long val;
	u32 notcopied_len;
	compat_size_t tocopy_len;

	copylen = iovcnt * sizeof(struct compat_iovec);

	if (unlikely(iovcnt >= 0xffffffff))
		return PPM_FAILURE_BUFFER_FULL;

	if (unlikely(copylen >= STR_STORAGE_SIZE))
		return PPM_FAILURE_BUFFER_FULL;

	if (unlikely(ppm_copy_from_user(args->str_storage, iovsrc, copylen)))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	iov = (const struct compat_iovec *)(args->str_storage);

	targetbuf += copylen;
	targetbuflen -= copylen;

	/*
	 * Size
	 */
	if (flags & PRB_FLAG_PUSH_SIZE) {
		for (j = 0; j < iovcnt; j++)
			size += iov[j].iov_len;

		/*
		 * Size is the total size of the buffers provided by the user. The number of
		 * received bytes can be smaller
		 */
		if ((flags & PRB_FLAG_IS_WRITE) == 0)
			if (size > retval)
				size = retval;

		res = val_to_ring(args, size, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	/*
	 * data
	 */
	if (flags & PRB_FLAG_PUSH_DATA) {
		if (retval > 0 && iovcnt > 0) {
			/*
			 * Retrieve the FD. It will be used for dynamic snaplen calculation.
			 */
			if (!args->is_socketcall) {
				ppm_syscall_get_arguments(current, args->regs, syscall_args);
				val = syscall_args[0];
			} else
				val = args->socketcall_args[0];
			args->fd = (int)val;

			/*
			 * Merge the buffers
			 */
			bufsize = 0;

			for (j = 0; j < iovcnt; j++) {
				if ((flags & PRB_FLAG_IS_WRITE) == 0) {
					if (bufsize >= retval) {
						ASSERT(bufsize >= retval);

						/*
						 * Copied all the data even if we haven't reached the
						 * end of the buffer.
						 * Copy must stop here.
						 */
						break;
					}

					tocopy_len = min(iov[j].iov_len, (compat_size_t)((size_t)retval - bufsize));
					tocopy_len = min(tocopy_len, (compat_size_t)(targetbuflen - bufsize - 1));
				} else {
					tocopy_len = min(iov[j].iov_len, (compat_size_t)(targetbuflen - bufsize - 1));
				}

				notcopied_len = (int)ppm_copy_from_user(targetbuf + bufsize,
									compat_ptr(iov[j].iov_base),
						tocopy_len);

				if (unlikely(notcopied_len != 0)) {
					/*
					 * This means we had a page fault. Skip this event.
					 */
					return PPM_FAILURE_INVALID_USER_MEMORY;
				}

				bufsize += tocopy_len;

				if (tocopy_len != iov[j].iov_len) {
					/*
					 * No space left in the args->str_storage buffer.
					 * Copy must stop here.
					 */
					break;
				}
			}

			args->enforce_snaplen = true;

			res = val_to_ring(args,
				(unsigned long)targetbuf,
				bufsize,
				false,
				0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		} else {
			res = val_to_ring(args, 0, 0, false, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		}
	}

	return PPM_SUCCESS;
}
#endif /* CONFIG_COMPAT */
#endif /* UDIG */

/*
 * STANDARD FILLERS
 */

/*
 * AUTOFILLER
 * In simple cases in which extracting an event is just a matter of moving the
 * arguments to the buffer, this filler can be used instead of writing a
 * filler function.
 * The arguments to extract are be specified in g_ppm_events.
 */
int f_sys_autofill(struct event_filler_arguments *args)
{
	int res;
	syscall_arg_t syscall_args[6] = {0};
	syscall_arg_t val;
	u32 j;
	int64_t retval;

	const struct ppm_event_entry *evinfo = &g_ppm_events[args->event_type];
	ASSERT(evinfo->n_autofill_args <= PPM_MAX_AUTOFILL_ARGS);

	for (j = 0; j < evinfo->n_autofill_args; j++) {
		if (evinfo->autofill_args[j].id >= 0) {
#ifdef _HAS_SOCKETCALL
			if (args->is_socketcall && evinfo->paramtype == APT_SOCK) {
				val = args->socketcall_args[evinfo->autofill_args[j].id];
			} else
#endif
			{
				/*
				 * Regular argument
				 */
				ppm_syscall_get_arguments(current, args->regs, syscall_args);
				val = syscall_args[evinfo->autofill_args[j].id];
			}

			res = val_to_ring(args, val, 0, true, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		} else if (evinfo->autofill_args[j].id == AF_ID_RETVAL) {
			/*
			 * Return value
			 */
			retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
			res = val_to_ring(args, retval, 0, false, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		} else if (evinfo->autofill_args[j].id == AF_ID_USEDEFAULT) {
			/*
			 * Default Value
			 */
			res = val_to_ring(args, evinfo->autofill_args[j].default_val, 0, false, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		} else {
			ASSERT(false);
		}
	}

	return add_sentinel(args);
}
