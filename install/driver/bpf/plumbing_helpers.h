/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __PLUMBING_HELPERS_H
#define __PLUMBING_HELPERS_H

#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/fdtable.h>

#include "types.h"
#include "builtins.h"

#ifdef CAPTURE_SOCKETCALL
#include <linux/net.h>
#endif

#define _READ(P) ({ typeof(P) _val;					\
		    bpf_probe_read_kernel(&_val, sizeof(_val), &P);	\
		    _val;						\
		 })
#define _READ_KERNEL(P) _READ(P)
#define _READ_USER(P) ({ typeof(P) _val;				\
			 bpf_probe_read_user(&_val, sizeof(_val), &P);	\
			 _val;						\
		 })

#ifdef BPF_DEBUG
#define bpf_printk(fmt, ...)					\
	do {							\
		char s[] = fmt;					\
		bpf_trace_printk(s, sizeof(s), ##__VA_ARGS__);	\
	} while (0)
#else
#define bpf_printk(fmt, ...)
#endif

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
static __always_inline int __stash_args(unsigned long long id,
					unsigned long *args)
{
	int ret = bpf_map_update_elem(&stash_map, &id, args, BPF_ANY);

	if (ret)
		bpf_printk("error stashing arguments for %d:%d\n", id, ret);

	return ret;
}

static __always_inline int stash_args(unsigned long *args)
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	return __stash_args(id, args);
}

static __always_inline unsigned long *__unstash_args(unsigned long long id)
{
	struct sys_stash_args *args;

	args = bpf_map_lookup_elem(&stash_map, &id);
	if (!args)
		return NULL;

	return args->args;
}

static __always_inline unsigned long *unstash_args(void)
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	return __unstash_args(id);
}

static __always_inline void delete_args(void)
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	bpf_map_delete_elem(&stash_map, &id);
}
#endif

/* Can be called just from an exit event
 */
static __always_inline long bpf_syscall_get_retval(void *ctx)
{
	struct sys_exit_args *args = (struct sys_exit_args *)ctx;

	return args->ret;
}

/* Can be called from both enter and exit event, id is at the same
 * offset in both struct sys_enter_args and struct sys_exit_args
 */
static __always_inline long bpf_syscall_get_nr(void *ctx)
{
	struct sys_enter_args *args = (struct sys_enter_args *)ctx;
	long id = 0;

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS

	struct pt_regs *regs = (struct pt_regs *)args->regs;

#ifdef CONFIG_X86_64

	/* See here for the definition:
	 * https://github.com/torvalds/linux/blob/69cb6c6556ad89620547318439d6be8bb1629a5a/arch/x86/include/asm/syscall.h#L40
	 */	
	id = _READ(regs->orig_ax);

#elif CONFIG_ARM64

	/* See here for the definition:
	 * https://github.com/torvalds/linux/blob/69cb6c6556ad89620547318439d6be8bb1629a5a/arch/arm64/include/asm/syscall.h#L23
	 */	
	id = _READ(regs->syscallno);

#elif CONFIG_S390

	/* See here for the definition:
	 * https://github.com/torvalds/linux/blob/69cb6c6556ad89620547318439d6be8bb1629a5a/arch/s390/include/asm/syscall.h#L24
	 */
	id = _READ(regs->int_code);
	id = id & 0xffff;

#endif /* CONFIG_X86_64 */

#else

	id = args->id;

#endif /* BPF_SUPPORTS_RAW_TRACEPOINTS */

	return id;
}

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
static __always_inline unsigned long bpf_syscall_get_argument_from_args(unsigned long *args,
									int idx)
{
	unsigned long arg = 0;

	if(idx <= 5)
	{
		arg = args[idx];
	}

	return arg;
}
#endif

static __always_inline unsigned long bpf_syscall_get_argument_from_ctx(void *ctx,
								       int idx)
{
	unsigned long arg = 0;

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS

	struct sys_enter_args *args = (struct sys_enter_args *)ctx;
	struct pt_regs *regs = (struct pt_regs *)args->regs;

#ifdef CONFIG_X86_64

	/* See here for the definition:
	 * https://github.com/libbpf/libbpf/blob/master/src/bpf_tracing.h#L75-L87
	 */
	switch (idx) {
	case 0:
		arg = _READ(regs->di);
		break;
	case 1:
		arg = _READ(regs->si);
		break;
	case 2:
		arg = _READ(regs->dx);
		break;
	case 3:
		arg = _READ(regs->r10);
		break;
	case 4:
		arg = _READ(regs->r8);
		break;
	case 5:
		arg = _READ(regs->r9);
		break;
	default:
		arg = 0;
	}

#elif CONFIG_ARM64

	/* See here for the definition:
	 * https://github.com/libbpf/libbpf/blob/master/src/bpf_tracing.h#L166-L178 
	 */
	struct user_pt_regs *user_regs = (struct user_pt_regs *)args->regs;
	switch (idx) {
	case 0:
		arg = _READ(regs->orig_x0);
		break;
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
		arg = _READ(user_regs->regs[idx]);
		break;
	default:
		arg = 0;
	}

#elif CONFIG_S390
	
	/* See here for the definition:
	 * https://github.com/libbpf/libbpf/blob/master/src/bpf_tracing.h#L132-L144
	 */
	user_pt_regs *user_regs = (user_pt_regs *)args->regs;
	switch (idx) {
	case 0:
		arg = _READ(regs->orig_gpr2);
		break;
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
		arg = _READ(user_regs->gprs[idx+2]);
		break;
	default:
		arg = 0;
	}

#endif /* CONFIG_X86_64 */

#else

	unsigned long *args = unstash_args();
	if (args)
		arg = bpf_syscall_get_argument_from_args(args, idx);
	else
		arg = 0;
		
#endif /* BPF_SUPPORTS_RAW_TRACEPOINTS */

	return arg;
}

#ifdef CAPTURE_SOCKETCALL
static __always_inline unsigned long bpf_syscall_get_socketcall_arg(void *ctx, int idx)
{
	unsigned long arg = 0;
	unsigned long args_pointer = 0;

	args_pointer = bpf_syscall_get_argument_from_ctx(ctx, 1);
	bpf_probe_read_user(&arg, sizeof(unsigned long), (void*)(args_pointer + (idx * sizeof(unsigned long))));

	return arg;
}
#endif /* CAPTURE_SOCKETCALL */

static __always_inline unsigned long bpf_syscall_get_argument(struct filler_data *data,
							      int idx)
{
#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS

/* We define it here because we support socket calls only on kernels with BPF_SUPPORTS_RAW_TRACEPOINTS */
#ifdef CAPTURE_SOCKETCALL
	if(bpf_syscall_get_nr(data->ctx) == __NR_socketcall)
	{
		return bpf_syscall_get_socketcall_arg(data->ctx, idx);
	}
#endif /* CAPTURE_SOCKETCALL */
	return bpf_syscall_get_argument_from_ctx(data->ctx, idx);
#else
	return bpf_syscall_get_argument_from_args(data->args, idx);
#endif
}

static __always_inline char *get_frame_scratch_area(unsigned int cpu)
{
	char *scratchp;

	scratchp = bpf_map_lookup_elem(&frame_scratch_map, &cpu);
	if (!scratchp)
		bpf_printk("frame scratch NULL\n");

	return scratchp;
}

static __always_inline char *get_tmp_scratch_area(unsigned int cpu)
{
	char *scratchp;

	scratchp = bpf_map_lookup_elem(&tmp_scratch_map, &cpu);
	if (!scratchp)
		bpf_printk("tmp scratch NULL\n");

	return scratchp;
}

static __always_inline const struct syscall_evt_pair *get_syscall_info(int id)
{
	const struct syscall_evt_pair *p =
			bpf_map_lookup_elem(&syscall_table, &id);

	if (!p)
		bpf_printk("no syscall_info for %d\n", id);

	return p;
}

static __always_inline bool is_syscall_interesting(int id)
{
	bool *enabled = bpf_map_lookup_elem(&interesting_syscalls_table, &id);

	if (!enabled)
	{
		bpf_printk("no syscall_info for %d\n", id);
		return false;
	}

	return *enabled;
}

static __always_inline const struct ppm_event_info *get_event_info(ppm_event_code event_type)
{
	const struct ppm_event_info *e =
		bpf_map_lookup_elem(&event_info_table, &event_type);

	if (!e)
		bpf_printk("no event info for %d\n", event_type);

	return e;
}

static __always_inline const struct ppm_event_entry *get_event_filler_info(ppm_event_code event_type)
{
	const struct ppm_event_entry *e;

	e = bpf_map_lookup_elem(&fillers_table, &event_type);
	if (!e)
		bpf_printk("no filler info for %d\n", event_type);

	return e;
}

static __always_inline struct scap_bpf_settings *get_bpf_settings(void)
{
	struct scap_bpf_settings *settings;
	int id = 0;

	settings = bpf_map_lookup_elem(&settings_map, &id);
	if (!settings)
		bpf_printk("settings NULL\n");

	return settings;
}

static __always_inline struct scap_bpf_per_cpu_state *get_local_state(unsigned int cpu)
{
	struct scap_bpf_per_cpu_state *state;

	state = bpf_map_lookup_elem(&local_state_map, &cpu);
	if (!state)
		bpf_printk("state NULL\n");

	return state;
}

static __always_inline bool acquire_local_state(struct scap_bpf_per_cpu_state *state)
{
	if (state->in_use) {
		bpf_printk("acquire_local_state: already in use\n");
		return false;
	}

	state->in_use = true;
	return true;
}

static __always_inline bool release_local_state(struct scap_bpf_per_cpu_state *state)
{
	if (!state->in_use) {
		bpf_printk("release_local_state: already not in use\n");
		return false;
	}

	state->in_use = false;
	return true;
}

static __always_inline int init_filler_data(void *ctx,
					    struct filler_data *data,
					    bool is_syscall)
{
	unsigned int cpu;

	data->ctx = ctx;

	data->settings = get_bpf_settings();
	if (!data->settings)
		return PPM_FAILURE_BUG;

	cpu = bpf_get_smp_processor_id();

	data->buf = get_frame_scratch_area(cpu);
	if (!data->buf)
		return PPM_FAILURE_BUG;

	data->state = get_local_state(cpu);
	if (!data->state)
		return PPM_FAILURE_BUG;

	data->tmp_scratch = get_tmp_scratch_area(cpu);
	if (!data->tmp_scratch)
		return PPM_FAILURE_BUG;

	data->evt = get_event_info(data->state->tail_ctx.evt_type);
	if (!data->evt)
		return PPM_FAILURE_BUG;

	data->filler_info = get_event_filler_info(data->state->tail_ctx.evt_type);
	if (!data->filler_info)
		return PPM_FAILURE_BUG;

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
	if (is_syscall) {
		data->args = unstash_args();
		if (!data->args)
			return PPM_SKIP_EVENT;
	}
#endif

	data->curarg_already_on_frame = false;
	data->fd = -1;

	return PPM_SUCCESS;
}

static __always_inline int bpf_test_bit(int nr, unsigned long *addr)
{
	return 1UL & (_READ(addr[BIT_WORD(nr)]) >> (nr & (BITS_PER_LONG - 1)));
}

#if defined(CAPTURE_SCHED_PROC_FORK) || defined(CAPTURE_SCHED_PROC_EXEC)
static __always_inline bool bpf_drop_syscall_exit_events(void *ctx, ppm_event_code evt_type)
{
	long ret = 0;
	switch (evt_type)
	{
		/* On s390x, clone and fork child events will be generated but
		 * due to page faults, no args/envp information will be collected.
		 * Also no child events appear for clone3 syscall.
		 *
		 * Because child events are covered by CAPTURE_SCHED_PROC_FORK,
		 * let proactively ignore them.
		 */
#ifdef CAPTURE_SCHED_PROC_FORK
		case PPME_SYSCALL_CLONE_20_X:
		case PPME_SYSCALL_FORK_20_X:
		case PPME_SYSCALL_VFORK_20_X:
		case PPME_SYSCALL_CLONE3_X:
			ret = bpf_syscall_get_retval(ctx);
			/* We ignore only child events, so ret == 0! */
			return ret == 0;
#endif

		/* If `CAPTURE_SCHED_PROC_EXEC` logic is enabled we collect execve-family
		 * exit events through a dedicated tracepoint so we can ignore them here.
		 */
#ifdef CAPTURE_SCHED_PROC_EXEC
		case PPME_SYSCALL_EXECVE_19_X:
		case PPME_SYSCALL_EXECVEAT_X:
			ret = bpf_syscall_get_retval(ctx);
			/* We ignore only successful events, so ret == 0! */
			return ret == 0;
#endif

		default:
			break;
	}
	return false;
}
#endif

static __always_inline bool drop_event(void *ctx,
				       struct scap_bpf_per_cpu_state *state,
				       ppm_event_code evt_type,
				       struct scap_bpf_settings *settings,
				       enum syscall_flags drop_flags)
{
	if (!settings->dropping_mode)
		return false;

	switch (evt_type) {
	case PPME_SYSCALL_CLOSE_X:
	case PPME_SOCKET_BIND_X: {
		long ret = bpf_syscall_get_retval(ctx);

		if (ret < 0)
			return true;

		break;
	}
	case PPME_SYSCALL_CLOSE_E: {
		struct sys_enter_args *args;
		struct files_struct *files;
		struct task_struct *task;
		unsigned long *open_fds;
		struct fdtable *fdt;
		int close_fd;
		int max_fds;

		close_fd = bpf_syscall_get_argument_from_ctx(ctx, 0);
		if (close_fd < 0)
			return true;

		task = (struct task_struct *)bpf_get_current_task();
		if (!task)
			break;

		files = _READ(task->files);
		if (!files)
			break;

		fdt = _READ(files->fdt);
		if (!fdt)
			break;

		max_fds = _READ(fdt->max_fds);
		if (close_fd >= max_fds)
			return true;

		open_fds = _READ(fdt->open_fds);
		if (!open_fds)
			break;

		if (!bpf_test_bit(close_fd, open_fds))
			return true;

		break;
	}
	case PPME_SYSCALL_FCNTL_E:
	case PPME_SYSCALL_FCNTL_X: {
		long cmd = bpf_syscall_get_argument_from_ctx(ctx, 1);

		if (cmd != F_DUPFD && cmd != F_DUPFD_CLOEXEC)
			return true;

		break;
	}
	default:
		break;
	}

	if (drop_flags & UF_NEVER_DROP)
		return false;

	if (drop_flags & UF_ALWAYS_DROP)
		return true;

	if (state->tail_ctx.ts % 1000000000 >= 1000000000 /
	    settings->sampling_ratio) {
		if (!settings->is_dropping) {
			settings->is_dropping = true;
			state->tail_ctx.evt_type = PPME_DROP_E;
			return false;
		}

		return true;
	}

	if (settings->is_dropping) {
		settings->is_dropping = false;
		state->tail_ctx.evt_type = PPME_DROP_X;
		return false;
	}

	return false;
}

static __always_inline void reset_tail_ctx(struct scap_bpf_per_cpu_state *state,
					   ppm_event_code evt_type,
					   unsigned long long ts)
{
	state->tail_ctx.evt_type = evt_type;
	state->tail_ctx.ts = ts;
	state->tail_ctx.curarg = 0;
	state->tail_ctx.curoff = 0;
	state->tail_ctx.len = 0;
	state->tail_ctx.prev_res = 0;
}

static __always_inline void call_filler(void *ctx,
					void *stack_ctx,
					ppm_event_code evt_type,
					enum syscall_flags drop_flags)
{
	struct scap_bpf_settings *settings;
	const struct ppm_event_entry *filler_info;
	struct scap_bpf_per_cpu_state *state;
	unsigned long long pid;
	unsigned long long ts;
	unsigned int cpu;

	cpu = bpf_get_smp_processor_id();

	state = get_local_state(cpu);
	if (!state)
		return;

	settings = get_bpf_settings();
	if (!settings)
		return;

	if (!acquire_local_state(state))
		return;

	if (cpu == 0 && state->hotplug_cpu != 0) {
		evt_type = PPME_CPU_HOTPLUG_E;
		drop_flags = UF_NEVER_DROP;
	}

	ts = settings->boot_time + bpf_ktime_get_boot_ns();
	reset_tail_ctx(state, evt_type, ts);

	/* drop_event can change state->tail_ctx.evt_type */
	if (drop_event(stack_ctx, state, evt_type, settings, drop_flags))
		goto cleanup;

	++state->n_evts;

	filler_info = get_event_filler_info(state->tail_ctx.evt_type);
	if (!filler_info)
		goto cleanup;

	bpf_tail_call(ctx, &tail_map, filler_info->filler_id);
	bpf_printk("Can't tail call filler evt=%d, filler=%d\n",
		   state->tail_ctx.evt_type,
		   filler_info->filler_id);

cleanup:
	release_local_state(state);
}

#if defined(CAPTURE_SOCKETCALL) && defined(BPF_SUPPORTS_RAW_TRACEPOINTS)
static __always_inline long convert_network_syscalls(void *ctx)
{
	int socketcall_id = (int)bpf_syscall_get_argument_from_ctx(ctx, 0);

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
#if defined(CONFIG_S390) && defined(__NR_accept4)
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
#endif

#endif
