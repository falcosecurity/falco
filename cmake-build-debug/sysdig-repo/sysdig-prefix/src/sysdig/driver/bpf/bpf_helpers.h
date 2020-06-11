/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

static void *(*bpf_map_lookup_elem)(void *map, void *key) =
	(void *)BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value,
				  unsigned long long flags) =
	(void *)BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
	(void *)BPF_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
	(void *)BPF_FUNC_probe_read;
static unsigned long long (*bpf_ktime_get_ns)(void) =
	(void *)BPF_FUNC_ktime_get_ns;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	(void *)BPF_FUNC_trace_printk;
static void (*bpf_tail_call)(void *ctx, void *map, int index) =
	(void *)BPF_FUNC_tail_call;
static unsigned long long (*bpf_get_smp_processor_id)(void) =
	(void *)BPF_FUNC_get_smp_processor_id;
static unsigned long long (*bpf_get_current_pid_tgid)(void) =
	(void *)BPF_FUNC_get_current_pid_tgid;
static unsigned long long (*bpf_get_current_uid_gid)(void) =
	(void *)BPF_FUNC_get_current_uid_gid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) =
	(void *)BPF_FUNC_get_current_comm;
static int (*bpf_perf_event_read)(void *map, int index) =
	(void *)BPF_FUNC_perf_event_read;
static int (*bpf_clone_redirect)(void *ctx, int ifindex, int flags) =
	(void *)BPF_FUNC_clone_redirect;
static int (*bpf_redirect)(int ifindex, int flags) =
	(void *)BPF_FUNC_redirect;
static int (*bpf_perf_event_output)(void *ctx, void *map,
				    unsigned long long flags, void *data,
				    int size) =
	(void *)BPF_FUNC_perf_event_output;
static int (*bpf_get_stackid)(void *ctx, void *map, int flags) =
	(void *)BPF_FUNC_get_stackid;
static int (*bpf_probe_write_user)(void *dst, void *src, int size) =
	(void *)BPF_FUNC_probe_write_user;
static int (*bpf_current_task_under_cgroup)(void *map, int index) =
	(void *)BPF_FUNC_current_task_under_cgroup;
static int (*bpf_skb_get_tunnel_key)(void *ctx, void *key, int size, int flags) =
	(void *)BPF_FUNC_skb_get_tunnel_key;
static int (*bpf_skb_set_tunnel_key)(void *ctx, void *key, int size, int flags) =
	(void *)BPF_FUNC_skb_set_tunnel_key;
static int (*bpf_skb_get_tunnel_opt)(void *ctx, void *md, int size) =
	(void *)BPF_FUNC_skb_get_tunnel_opt;
static int (*bpf_skb_set_tunnel_opt)(void *ctx, void *md, int size) =
	(void *)BPF_FUNC_skb_set_tunnel_opt;
static unsigned long long (*bpf_get_prandom_u32)(void) =
	(void *)BPF_FUNC_get_prandom_u32;
static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
	(void *)BPF_FUNC_xdp_adjust_head;
static int (*bpf_probe_read_str)(void *dst, u64 size, const void *unsafe_ptr) =
	(void *)BPF_FUNC_probe_read_str;
static u64 (*bpf_get_current_task)(void) =
	(void *)BPF_FUNC_get_current_task;
static int (*bpf_skb_load_bytes)(void *ctx, int off, void *to, int len) =
	(void *)BPF_FUNC_skb_load_bytes;
static int (*bpf_skb_store_bytes)(void *ctx, int off, void *from, int len, int flags) =
	(void *)BPF_FUNC_skb_store_bytes;
static int (*bpf_l3_csum_replace)(void *ctx, int off, int from, int to, int flags) =
	(void *)BPF_FUNC_l3_csum_replace;
static int (*bpf_l4_csum_replace)(void *ctx, int off, int from, int to, int flags) =
	(void *)BPF_FUNC_l4_csum_replace;
static int (*bpf_skb_under_cgroup)(void *ctx, void *map, int index) =
	(void *)BPF_FUNC_skb_under_cgroup;
static int (*bpf_skb_change_head)(void *, int len, int flags) =
	(void *)BPF_FUNC_skb_change_head;

#endif
