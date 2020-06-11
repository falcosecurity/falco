/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef PPM_RINGBUFFER_H_
#define PPM_RINGBUFFER_H_

#ifdef __KERNEL__
#include <linux/types.h>
#endif

static const __u32 RING_BUF_SIZE = 8 * 1024 * 1024;
static const __u32 MIN_USERSPACE_READ_SIZE = 128 * 1024;

/*
 * This gets mapped to user level, so we want to keep it as clean as possible
 */
struct ppm_ring_buffer_info {
	volatile __u32 head;
	volatile __u32 tail;
	volatile __u64 n_evts;			/* Total number of events that were received by the driver. */
	volatile __u64 n_drops_buffer;		/* Number of dropped events (buffer full). */
	volatile __u64 n_drops_pf;		/* Number of dropped events (page faults). */
	volatile __u64 n_preemptions;		/* Number of preemptions. */
	volatile __u64 n_context_switches;	/* Number of received context switch events. */
};

#endif /* PPM_RINGBUFFER_H_ */
