/*

Copyright (C) 2022 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#include "quirks.h"

#include <generated/utsrelease.h>
#include <uapi/linux/bpf.h>
#if __has_include(<asm/rwonce.h>)
#include <asm/rwonce.h>
#endif
#include <linux/sched.h>

#include "../driver_config.h"
#include "../ppm_events_public.h"
#include "bpf_helpers.h"
#include "types.h"
#include "maps.h"
#include "plumbing_helpers.h"
#include "ring_helpers.h"
#include "filler_helpers.h"
#include "fillers.h"
#include "builtins.h"

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
#define BPF_PROBE(prefix, event, type)			\
__bpf_section(TP_NAME #event)				\
int bpf_##event(struct type *ctx)
#else
#define BPF_PROBE(prefix, event, type)			\
__bpf_section(TP_NAME prefix #event)			\
int bpf_##event(struct type *ctx)
#endif

BPF_PROBE("raw_syscalls/", sys_enter, sys_enter_args)
{
	const struct syscall_evt_pair *sc_evt;
	ppm_event_code evt_type;
	int drop_flags;
	long id;
	bool enabled;

	if (bpf_in_ia32_syscall())
		return 0;

	id = bpf_syscall_get_nr(ctx);
	if (id < 0 || id >= SYSCALL_TABLE_SIZE)
		return 0;

#if defined(CAPTURE_SOCKETCALL) && defined(BPF_SUPPORTS_RAW_TRACEPOINTS)
	if(id == __NR_socketcall)
	{
		id = convert_network_syscalls(ctx);
	}
#endif

	enabled = is_syscall_interesting(id);
	if (!enabled)
	{
		return 0;
	}

	sc_evt = get_syscall_info(id);
	if (!sc_evt)
		return 0;

	if (sc_evt->flags & UF_USED) {
		evt_type = sc_evt->enter_event_type;
		drop_flags = sc_evt->flags;
	} else {
		evt_type = PPME_GENERIC_E;
		drop_flags = UF_ALWAYS_DROP;
	}

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
	call_filler(ctx, ctx, evt_type, drop_flags);
#else
	/* Duplicated here to avoid verifier madness */
	struct sys_enter_args stack_ctx;

	memcpy(stack_ctx.args, ctx->args, sizeof(ctx->args));
	if (stash_args(stack_ctx.args))
		return 0;

	call_filler(ctx, &stack_ctx, evt_type, drop_flags);
#endif
	return 0;
}

BPF_PROBE("raw_syscalls/", sys_exit, sys_exit_args)
{
	const struct syscall_evt_pair *sc_evt;
	ppm_event_code evt_type;
	int drop_flags;
	long id;
	bool enabled;

	if (bpf_in_ia32_syscall())
		return 0;

	id = bpf_syscall_get_nr(ctx);
	if (id < 0 || id >= SYSCALL_TABLE_SIZE)
		return 0;

#if defined(CAPTURE_SOCKETCALL) && defined(BPF_SUPPORTS_RAW_TRACEPOINTS)
	if(id == __NR_socketcall)
	{
		id = convert_network_syscalls(ctx);
	}
#endif

	enabled = is_syscall_interesting(id);
	if (!enabled)
	{
		return 0;
	}

	sc_evt = get_syscall_info(id);
	if (!sc_evt)
		return 0;

	if (sc_evt->flags & UF_USED) {
		evt_type = sc_evt->exit_event_type;
		drop_flags = sc_evt->flags;
	} else {
		evt_type = PPME_GENERIC_X;
		drop_flags = UF_ALWAYS_DROP;
	}

#if defined(CAPTURE_SCHED_PROC_FORK) || defined(CAPTURE_SCHED_PROC_EXEC)
	if(bpf_drop_syscall_exit_events(ctx, evt_type))
		return 0;
#endif

	call_filler(ctx, ctx, evt_type, drop_flags);
	return 0;
}

BPF_PROBE("sched/", sched_process_exit, sched_process_exit_args)
{
	ppm_event_code evt_type;
	struct task_struct *task;
	unsigned int flags;

	task = (struct task_struct *)bpf_get_current_task();

	flags = _READ(task->flags);
	if (flags & PF_KTHREAD)
		return 0;

	evt_type = PPME_PROCEXIT_1_E;

	call_filler(ctx, ctx, evt_type, UF_NEVER_DROP);
	return 0;
}

BPF_PROBE("sched/", sched_switch, sched_switch_args)
{
	ppm_event_code evt_type;

	evt_type = PPME_SCHEDSWITCH_6_E;

	call_filler(ctx, ctx, evt_type, 0);
	return 0;
}

#ifdef CAPTURE_PAGE_FAULTS
static __always_inline int bpf_page_fault(struct page_fault_args *ctx)
{
	ppm_event_code evt_type;

	evt_type = PPME_PAGE_FAULT_E;

	call_filler(ctx, ctx, evt_type, UF_ALWAYS_DROP);
	return 0;
}

BPF_PROBE("exceptions/", page_fault_user, page_fault_args)
{
	return bpf_page_fault(ctx);
}

BPF_PROBE("exceptions/", page_fault_kernel, page_fault_args)
{
	return bpf_page_fault(ctx);
}
#endif

BPF_PROBE("signal/", signal_deliver, signal_deliver_args)
{
	ppm_event_code evt_type;

	evt_type = PPME_SIGNALDELIVER_E;

	call_filler(ctx, ctx, evt_type, UF_ALWAYS_DROP);
	return 0;
}

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
__bpf_section(TP_NAME "sched/sched_process_fork")
int bpf_sched_process_fork(struct sched_process_fork_args *ctx)
{
	ppm_event_code evt_type;
	struct sys_stash_args args;
	unsigned long *argsp;

	argsp = __unstash_args(ctx->parent_pid);
	if (!argsp)
		return 0;

	memcpy(&args, argsp, sizeof(args));

	__stash_args(ctx->child_pid, args.args);

	return 0;
}
#endif

#ifdef CAPTURE_SCHED_PROC_EXEC
BPF_PROBE("sched/", sched_process_exec, sched_process_exec_args)
{
	struct scap_bpf_settings *settings;
	/* We will always send an execve exit event. */
	ppm_event_code event_type = PPME_SYSCALL_EXECVE_19_X;

	/* We are not interested in kernel threads. */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	unsigned int flags = _READ(task->flags);
	if(flags & PF_KTHREAD)
	{
		return 0;
	}

	/* Reset the tail context in the CPU state map. */
	uint32_t cpu = bpf_get_smp_processor_id();
	struct scap_bpf_per_cpu_state * state = get_local_state(cpu);
	if(!state)
	{
		return 0;
	}

	settings = get_bpf_settings();
	if(!settings)
	{
		return 0;
	}
	uint64_t ts = settings->boot_time + bpf_ktime_get_boot_ns();
	reset_tail_ctx(state, event_type, ts);
	++state->n_evts;


	int filler_code = PPM_FILLER_sched_prog_exec;
	bpf_tail_call(ctx, &tail_map, filler_code);
	bpf_printk("Can't tail call filler 'sched_proc_exec' evt=%d, filler=%d\n",
		   event_type,
		   filler_code);	
	return 0;
}
#endif /* CAPTURE_SCHED_PROC_EXEC */

#ifdef CAPTURE_SCHED_PROC_FORK
__bpf_section("raw_tracepoint/sched_process_fork")
int bpf_sched_process_fork(struct sched_process_fork_raw_args *ctx)
{
	struct scap_bpf_settings *settings;
	/* We will always send a clone exit event. */
	ppm_event_code event_type = PPME_SYSCALL_CLONE_20_X;

	/* We are not interested in kernel threads. */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	unsigned int flags = _READ(task->flags);
	if(flags & PF_KTHREAD)
	{
		return 0;
	}

	/* Reset the tail context in the CPU state map. */
	uint32_t cpu = bpf_get_smp_processor_id();
	struct scap_bpf_per_cpu_state * state = get_local_state(cpu);
	if(!state)
	{
		return 0;
	}

	settings = get_bpf_settings();
	if(!settings)
	{
		return 0;
	}
	uint64_t ts = settings->boot_time + bpf_ktime_get_boot_ns();
	reset_tail_ctx(state, event_type, ts);
	++state->n_evts;

	int filler_code = PPM_FILLER_sched_prog_fork;
	bpf_tail_call(ctx, &tail_map, filler_code);
	bpf_printk("Can't tail call filler 'sched_proc_fork' evt=%d, filler=%d\n",
		   event_type,
		   filler_code);	
	return 0;
}
#endif /* CAPTURE_SCHED_PROC_FORK */

char kernel_ver[] __bpf_section("kernel_version") = UTS_RELEASE;

char __license[] __bpf_section("license") = "GPL";

char probe_ver[] __bpf_section("probe_version") = DRIVER_VERSION;

char probe_commit[] __bpf_section("build_commit") = DRIVER_COMMIT;

uint64_t probe_api_ver __bpf_section("api_version") = PPM_API_CURRENT_VERSION;

uint64_t probe_schema_ver __bpf_section("schema_version") = PPM_SCHEMA_CURRENT_VERSION;
