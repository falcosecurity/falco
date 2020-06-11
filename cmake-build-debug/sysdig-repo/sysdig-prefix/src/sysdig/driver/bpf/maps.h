/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __MAPS_H
#define __MAPS_H

#include "types.h"

struct bpf_map_def __bpf_section("maps") perf_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 0,
};

struct bpf_map_def __bpf_section("maps") tail_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = PPM_FILLER_MAX,
};

struct bpf_map_def __bpf_section("maps") syscall_code_routing_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = SYSCALL_TABLE_SIZE,
};

struct bpf_map_def __bpf_section("maps") syscall_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct syscall_evt_pair),
	.max_entries = SYSCALL_TABLE_SIZE,
};

struct bpf_map_def __bpf_section("maps") event_info_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct ppm_event_info),
	.max_entries = PPM_EVENT_MAX,
};

struct bpf_map_def __bpf_section("maps") fillers_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct ppm_event_entry),
	.max_entries = PPM_EVENT_MAX,
};

struct bpf_map_def __bpf_section("maps") frame_scratch_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = SCRATCH_SIZE,
	.max_entries = 0,
};

struct bpf_map_def __bpf_section("maps") tmp_scratch_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = SCRATCH_SIZE,
	.max_entries = 0,
};

struct bpf_map_def __bpf_section("maps") settings_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct sysdig_bpf_settings),
	.max_entries = 1,
};

struct bpf_map_def __bpf_section("maps") local_state_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct sysdig_bpf_per_cpu_state),
	.max_entries = 0,
};

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
struct bpf_map_def __bpf_section("maps") stash_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(struct sys_stash_args),
	.max_entries = 65535,
};
#endif

#endif
