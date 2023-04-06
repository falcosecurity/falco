/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/base/common.h>
#include <maps/maps.h>

/* All these helpers functions are getters, they return
 * the specific map value.
 */

/*=============================== SETTINGS ===========================*/

static __always_inline u64 maps__get_boot_time()
{
	return g_settings.boot_time;
}

static __always_inline uint32_t maps__get_snaplen()
{
	return g_settings.snaplen;
}

static __always_inline bool maps__get_dropping_mode()
{
	return g_settings.dropping_mode;
}

static __always_inline uint32_t maps__get_sampling_ratio()
{
	return g_settings.sampling_ratio;
}

/*=============================== SETTINGS ===========================*/

/*=============================== KERNEL CONFIGS ===========================*/

static __always_inline bool maps__get_is_dropping()
{
	return is_dropping;
}

static __always_inline void maps__set_is_dropping(bool value)
{
	is_dropping = value;
}

/*=============================== KERNEL CONFIGS ===========================*/

/*=============================== SAMPLING TABLES ===========================*/

static __always_inline uint8_t maps__64bit_sampling_syscall_table(u32 syscall_id)
{
	return g_64bit_sampling_syscall_table[syscall_id & (SYSCALL_TABLE_SIZE - 1)];
}

static __always_inline uint8_t maps__64bit_sampling_tracepoint_table(u32 event_id)
{
	return g_64bit_sampling_tracepoint_table[event_id < PPM_EVENT_MAX ? event_id : PPM_EVENT_MAX-1];
}

/*=============================== SAMPLING TABLES ===========================*/

/*=============================== SYSCALL-64 INTERESTING TABLE ===========================*/

static __always_inline bool maps__64bit_interesting_syscall(u32 syscall_id)
{
	return g_64bit_interesting_syscalls_table[syscall_id & (SYSCALL_TABLE_SIZE - 1)];
}

/*=============================== SYSCALL-64 INTERESTING TABLE ===========================*/

/*=============================== EVENT NUM PARAMS TABLE ===========================*/

static __always_inline u8 maps__get_event_num_params(u32 event_id)
{
	if(event_id < 0 || event_id >= PPM_EVENT_MAX)
	{
		return 0;
	}
	return g_event_params_table[event_id];
}

/*=============================== EVENT NUM PARAMS TABLE ===========================*/

/*=============================== PPM_SC TABLE ===========================*/

static __always_inline u16 maps__get_ppm_sc(u16 syscall_id)
{
	return g_ppm_sc_table[syscall_id & (SYSCALL_TABLE_SIZE - 1)];
}

/*=============================== PPM_SC TABLE ===========================*/

/*=============================== AUXILIARY MAPS ===========================*/

static __always_inline struct auxiliary_map *maps__get_auxiliary_map()
{
	u32 cpu_id = (u32)bpf_get_smp_processor_id();
	return (struct auxiliary_map *)bpf_map_lookup_elem(&auxiliary_maps, &cpu_id);
}

/*=============================== AUXILIARY MAPS ===========================*/

/*=============================== COUNTER MAPS ===========================*/

static __always_inline struct counter_map *maps__get_counter_map()
{
	u32 cpu_id = (u32)bpf_get_smp_processor_id();
	return (struct counter_map *)bpf_map_lookup_elem(&counter_maps, &cpu_id);
}

/*=============================== COUNTER MAPS ===========================*/

/*=============================== RINGBUF MAPS ===========================*/

static __always_inline struct ringbuf_map *maps__get_ringbuf_map()
{
	u32 cpu_id = (u32)bpf_get_smp_processor_id();
	return (struct ringbuf_map *)bpf_map_lookup_elem(&ringbuf_maps, &cpu_id);
}

/*=============================== RINGBUF MAPS ===========================*/
