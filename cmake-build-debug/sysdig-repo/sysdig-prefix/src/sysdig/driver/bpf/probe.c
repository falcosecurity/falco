/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#include "quirks.h"

#include <generated/utsrelease.h>
#include <uapi/linux/bpf.h>
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
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	int drop_flags;
	long id;

	if (bpf_in_ia32_syscall())
		return 0;

	id = bpf_syscall_get_nr(ctx);
	if (id < 0 || id >= SYSCALL_TABLE_SIZE)
		return 0;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

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
	call_filler(ctx, ctx, evt_type, settings, drop_flags);
#else
	/* Duplicated here to avoid verifier madness */
	struct sys_enter_args stack_ctx;

	memcpy(stack_ctx.args, ctx->args, sizeof(ctx->args));
	if (stash_args(stack_ctx.args))
		return 0;

	call_filler(ctx, &stack_ctx, evt_type, settings, drop_flags);
#endif
	return 0;
}

BPF_PROBE("raw_syscalls/", sys_exit, sys_exit_args)
{
	const struct syscall_evt_pair *sc_evt;
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	int drop_flags;
	long id;

	if (bpf_in_ia32_syscall())
		return 0;

	id = bpf_syscall_get_nr(ctx);
	if (id < 0 || id >= SYSCALL_TABLE_SIZE)
		return 0;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

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

	call_filler(ctx, ctx, evt_type, settings, drop_flags);
	return 0;
}

BPF_PROBE("sched/", sched_process_exit, sched_process_exit_args)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	struct task_struct *task;
	unsigned int flags;

	task = (struct task_struct *)bpf_get_current_task();

	flags = _READ(task->flags);
	if (flags & PF_KTHREAD)
		return 0;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	evt_type = PPME_PROCEXIT_1_E;

	call_filler(ctx, ctx, evt_type, settings, UF_NEVER_DROP);
	return 0;
}

BPF_PROBE("sched/", sched_switch, sched_switch_args)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	evt_type = PPME_SCHEDSWITCH_6_E;

	call_filler(ctx, ctx, evt_type, settings, 0);
	return 0;
}

static __always_inline int bpf_page_fault(struct page_fault_args *ctx)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->page_faults)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	evt_type = PPME_PAGE_FAULT_E;

	call_filler(ctx, ctx, evt_type, settings, UF_ALWAYS_DROP);
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

BPF_PROBE("signal/", signal_deliver, signal_deliver_args)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	evt_type = PPME_SIGNALDELIVER_E;

	call_filler(ctx, ctx, evt_type, settings, UF_ALWAYS_DROP);
	return 0;
}

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
__bpf_section(TP_NAME "sched/sched_process_fork")
int bpf_sched_process_fork(struct sched_process_fork_args *ctx)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	struct sys_stash_args args;
	unsigned long *argsp;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	argsp = __unstash_args(ctx->parent_pid);
	if (!argsp)
		return 0;

	memcpy(&args, argsp, sizeof(args));

	__stash_args(ctx->child_pid, args.args);

	return 0;
}
#endif

char kernel_ver[] __bpf_section("kernel_version") = UTS_RELEASE;

char probe_ver[] __bpf_section("probe_version") = PROBE_VERSION;
