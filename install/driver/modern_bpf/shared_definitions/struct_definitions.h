/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

/* Here we have all definitions required both by
 * BPF programs and `libpman` library.
 */

/* The auxiliary map can contain events of at most 64 KB.
 * Here we have 128 KB as dimension to guarantee the verifier
 * that there are always at least 64 KB free.
 */
#define AUXILIARY_MAP_SIZE 128 * 1024

/**
 * @brief General settings shared among all the CPUs.
 *
 */
struct capture_settings
{
	uint64_t boot_time;	 /* boot time. */
	uint32_t snaplen;	 /* we use it when we want to read a maximum size from a event and no more. */
	bool dropping_mode;	 /* this flag actives the sampling logic */
	uint32_t sampling_ratio; /* this config tells tracepoints when they have to drop events  */
};

/**
 * @brief This struct will temporally contain the event
 * before being pushed to userspace. It also contains two
 * placeholders for the payload position and the lengths position.
 *
 * To have more info about the event format, please look at `helpers/base/push_data.h`
 */
struct auxiliary_map
{
	uint8_t data[AUXILIARY_MAP_SIZE]; /* raw space to save our variable-size event. */
	uint64_t payload_pos;	       /* position of the first empty byte in the `data` buf. */
	uint8_t lengths_pos;	       /* position the first empty slot into the lengths array of the event. */
};

/* These per-cpu maps are used to carry the number of drops and
 * processed events.
 */

/**
 * @brief These per-cpu maps are used to carry the number of dropped and
 * processed events.
 */
struct counter_map
{
	uint64_t n_evts;		 /* Number of events correctly sent to userspace. */
	uint64_t n_drops_buffer;	 /* Number of drops due to a full ringbuf. */
	uint64_t n_drops_max_event_size; /* Number of drops due to an excessive event size (>64KB). */
};
