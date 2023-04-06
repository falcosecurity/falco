/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __RING_HELPERS_H
#define __RING_HELPERS_H

static __always_inline void write_evt_hdr(struct filler_data *data)
{
	struct ppm_evt_hdr *evt_hdr = (struct ppm_evt_hdr *)data->buf;

	evt_hdr->ts = data->state->tail_ctx.ts;
	evt_hdr->tid = bpf_get_current_pid_tgid() & 0xffffffff;
	evt_hdr->type = data->state->tail_ctx.evt_type;
	evt_hdr->nparams = data->evt->nparams;

	data->state->tail_ctx.curoff = sizeof(struct ppm_evt_hdr) +
				       sizeof(u16) * data->evt->nparams;
	data->state->tail_ctx.len = data->state->tail_ctx.curoff;
}

static __always_inline void fixup_evt_len(char *p, unsigned long len)
{
	struct ppm_evt_hdr *evt_hdr = (struct ppm_evt_hdr *)p;

	evt_hdr->len = len;
}

static __always_inline void fixup_evt_arg_len(char *p,
					      unsigned int argnum,
					      unsigned int arglen)
{
	if (argnum > PPM_MAX_EVENT_PARAMS)
	{
		return;
	}
	volatile unsigned int argnumv = argnum;
	*((u16 *)&p[sizeof(struct ppm_evt_hdr)] + (argnumv & (PPM_MAX_EVENT_PARAMS - 1))) = arglen;
}

static __always_inline int push_evt_frame(void *ctx,
					  struct filler_data *data)
{
	if (data->state->tail_ctx.curarg != data->evt->nparams) {
		bpf_printk("corrupted filler for event type %d (added %u args, should have added %u)\n",
			   data->state->tail_ctx.evt_type,
			   data->state->tail_ctx.curarg,
			   data->evt->nparams);
		return PPM_FAILURE_BUG;
	}

	if (data->state->tail_ctx.len > PERF_EVENT_MAX_SIZE)
	{
		return PPM_FAILURE_FRAME_SCRATCH_MAP_FULL;
	}

	fixup_evt_len(data->buf, data->state->tail_ctx.len);

#ifdef BPF_FORBIDS_ZERO_ACCESS
	int res = bpf_perf_event_output(ctx,
					&perf_map,
					BPF_F_CURRENT_CPU,
					data->buf,
					((data->state->tail_ctx.len - 1) & SCRATCH_SIZE_MAX) + 1);
#else
	int res = bpf_perf_event_output(ctx,
					&perf_map,
					BPF_F_CURRENT_CPU,
					data->buf,
					data->state->tail_ctx.len & SCRATCH_SIZE_MAX);
#endif
	if (res == -ENOENT || res == -EOPNOTSUPP) {
		/*
		 * ENOENT = likely a new CPU is online that wasn't
		 *          opened in userspace
		 *
		 * EOPNOTSUPP = likely a perf channel has been closed
		 *              because a CPU went offline
		 *
		 * Schedule a hotplug event on CPU 0
		 */
		struct scap_bpf_per_cpu_state *state = get_local_state(0);

		if (!state)
			return PPM_FAILURE_BUG;

		state->hotplug_cpu = bpf_get_smp_processor_id();
		bpf_printk("detected hotplug event, cpu=%d\n", state->hotplug_cpu);
	} else if (res == -ENOSPC) {
		bpf_printk("bpf_perf_buffer full\n");
		return PPM_FAILURE_BUFFER_FULL;
	} else if (res) {
		bpf_printk("bpf_perf_event_output failed, res=%d\n", res);
		return PPM_FAILURE_BUG;
	}

	return PPM_SUCCESS;
}

#endif
