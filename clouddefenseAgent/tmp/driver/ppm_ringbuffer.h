/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef PPM_RINGBUFFER_H_
#define PPM_RINGBUFFER_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#endif

/* This method validates the per-CPU buffer bytes dimension:
 * The single buffer dimension must be:
 * - greater than `2 * PAGE_SIZE`.
 * - a multiple of the system PAGE_SIZE.
 * - a power of 2.
 * 
 * Returns true if the buffer has a valid dimension.
 */
static inline bool validate_buffer_bytes_dim(unsigned long buf_bytes_dim, unsigned long page_size)
{
	return ((buf_bytes_dim > (2 * page_size)) && ((buf_bytes_dim % page_size) == 0) && ((buf_bytes_dim & (buf_bytes_dim - 1)) == 0));
}

/*
 * This gets mapped to user level, so we want to keep it as clean as possible
 */
struct ppm_ring_buffer_info {
	volatile __u32 head;
	volatile __u32 tail;
	volatile __u64 n_evts;			/* Total number of events that were received by the driver. */
	volatile __u64 n_drops_buffer;		/* Total number of kernel side drops due to full buffer, includes all categories below, likely higher than sum of syscall categories. */
	/*  Kernel side drops due to full buffer for categories of system calls. Not all system calls of interest are mapped into one of the categories. */
	volatile __u64 n_drops_buffer_clone_fork_enter;
	volatile __u64 n_drops_buffer_clone_fork_exit;
	volatile __u64 n_drops_buffer_execve_enter;
	volatile __u64 n_drops_buffer_execve_exit;
	volatile __u64 n_drops_buffer_connect_enter;
	volatile __u64 n_drops_buffer_connect_exit;
	volatile __u64 n_drops_buffer_open_enter;
	volatile __u64 n_drops_buffer_open_exit;
	volatile __u64 n_drops_buffer_dir_file_enter;
	volatile __u64 n_drops_buffer_dir_file_exit;
	volatile __u64 n_drops_buffer_other_interest_enter;		/* Category of other system calls of interest, not all other system calls that did not match a category from above. */
	volatile __u64 n_drops_buffer_other_interest_exit;
	volatile __u64 n_drops_pf;		/* Number of dropped events (page faults). */
	volatile __u64 n_preemptions;		/* Number of preemptions. */
	volatile __u64 n_context_switches;	/* Number of received context switch events. */
};

#endif /* PPM_RINGBUFFER_H_ */
