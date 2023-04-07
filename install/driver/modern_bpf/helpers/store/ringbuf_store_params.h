/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/base/push_data.h>
#include <helpers/extract/extract_from_kernel.h>

/* `reserved_size - sizeof(u64)` free space is enough because this is the max dimension
 * we put in the ring buffer in one atomic operation.
 */
#define CHECK_RINGBUF_SPACE(pos, reserved_size) pos >= reserved_size ? reserved_size - sizeof(u64) : pos

#define PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, size)                                                                         \
	__builtin_memcpy(&ringbuf->data[CHECK_RINGBUF_SPACE(ringbuf->payload_pos, ringbuf->reserved_event_size)], &param, size); \
	ringbuf->payload_pos += size;                                                                                            \
	*((u16 *)&ringbuf->data[CHECK_RINGBUF_SPACE(ringbuf->lengths_pos, ringbuf->reserved_event_size)]) = size;                \
	ringbuf->lengths_pos += sizeof(u16);

/* Concept of ringbuf(ring buffer):
 *
 * For fixed size events we directly reserve space into the ringbuf. We have
 * a dedicated ringbuf for every CPU. When we collect a fixed size event,
 * as a first thing, we try to reserve space inside the ringbuf. If the
 * operation is successful we save the pointer to this space, otherwise
 * if the buffer is full, we stop immediately the collection without
 * loosing further time.
 *
 * More precisely, in case of success we store the pointer into a struct
 * called `ringbuf_struct`:
 *
 * struct ringbuf_struct
 * {
 *	  u8 *data;	   // pointer to the space reserved in the ring buffer.
 *	  u64 payload_pos; // position of the first empty byte in the `data` buf.
 *	  u8 lengths_pos;  // position the first empty slot into the lengths array of the event.
 * };
 *
 * To better understand the two indexes `payload_pos` and `lengths_pos`
 * please see the description of the event format in
 * `helpers/base/push_data.h`
 *
 * As you may notice this structure is very similar to the `auxiliary_map` struct,
 * but there are some differences:
 * - In `ringbuf_struct` struct `data` is a pointer to some space in the ringbuf
 *   while in the auxamp is a buffer saved inside the struct.
 * - There is a `struct auxiliary_map` for every CPU, and all these structs
 *   are saved in a BPF map. This allow us to use the same struct between
 *   different BPF programs tail called, we have just to take the pointer
 * 	 to this struct and save it in our BPF stack. On the other side, the
 *   struct `ringbuf_struct` is created into the stack directly, we don't use
 * 	 a pointer. So we cannot pass this struct from a BPF program to another,
 *   but this is ok, because right now it is not possible to use a pointer to
 * 	 some space in the ringbuf outside the BPF program in which we call the
 * 	 reserve function. This is due to the fact taht we could cause a memory
 *   leakage, that is not obviously allowed in BPF.
 */

struct ringbuf_struct
{
	u8 *data;		 /* pointer to the space reserved in the ring buffer. */
	u64 payload_pos;	 /* position of the first empty byte in the `data` buf.*/
	u8 lengths_pos;		 /* position the first empty slot into the lengths array of the event. */
	u16 reserved_event_size; /* reserved size in the ringbuf. */
};

/////////////////////////////////
// RESERVE SPACE IN THE RINGBUF
////////////////////////////////

/**
 * @brief This helper is used to reserve some space inside the ringbuf
 * for that particular CPU. The number of CPU is taken directly inside
 * `maps__get_ringbuf_map()`.
 *
 * Please note: we need to pass the exact size to reserve, so we need
 * to know the event dimension at compile time.
 *
 * @param ringbuf pointer to the `ringbuf_struct`
 * @param event_size exact size of the fixed-size event
 * @return `1` in case of success, `0` in case of failure.
 */
static __always_inline u32 ringbuf__reserve_space(struct ringbuf_struct *ringbuf, u32 event_size)
{

	struct ringbuf_map *rb = maps__get_ringbuf_map();
	if(!rb)
	{
		return 0;
	}

	struct counter_map *counter = maps__get_counter_map();
	if(!counter)
	{
		return 0;
	}

	/* This counts the event seen by the drivers even if they are dropped because the buffer is full. */
	counter->n_evts++;

	/* If we are not able to reserve space we stop here
	 * the event collection.
	 */
	u8 *space = bpf_ringbuf_reserve(rb, event_size, 0);
	if(!space)
	{
		counter->n_drops_buffer++;
		return 0;
	}

	ringbuf->data = space;
	ringbuf->reserved_event_size = event_size;
	return 1;
}

/////////////////////////////////
// STORE EVENT HEADER IN THE RINGBUF
////////////////////////////////

/**
 * @brief Push the event header inside the ringbuf space.
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param event_type type of the event that we are storing into the ringbuf.
 * @param event_size exact size of the fixed-size event.
 */
static __always_inline void ringbuf__store_event_header(struct ringbuf_struct *ringbuf, u32 event_type)
{
	struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)ringbuf->data;
	u8 nparams = maps__get_event_num_params(event_type);
	hdr->ts = maps__get_boot_time() + bpf_ktime_get_boot_ns();
	hdr->tid = bpf_get_current_pid_tgid() & 0xffffffff;
	hdr->type = event_type;
	hdr->nparams = nparams;
	hdr->len = ringbuf->reserved_event_size;

	ringbuf->payload_pos = sizeof(struct ppm_evt_hdr) + nparams * sizeof(u16);
	ringbuf->lengths_pos = sizeof(struct ppm_evt_hdr);
}

/////////////////////////////////
// SUBMIT EVENT IN THE RINGBUF
////////////////////////////////

/**
 * @brief This method states that the collection of the event is
 * terminated.
 *
 * `BPF_RB_NO_WAKEUP` option allow to not notify the userspace
 * when a new event is submitted.
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 */
static __always_inline void ringbuf__submit_event(struct ringbuf_struct *ringbuf)
{
	bpf_ringbuf_submit(ringbuf->data, BPF_RB_NO_WAKEUP);
}

/////////////////////////////////
// STORE PARAM TYPE INTO RING BUFFER
////////////////////////////////

/* All these `ringbuf__store_(x)_param` helpers have the task
 * to store a particular param inside the ringbuf space.
 * Note: `push__` functions store only some bytes into this space
 * and increment the payload pos. To store an entire param
 * we could need one or more `push__` helpers and one final `push__param_len`
 * to save the overall param len into the `lengths_array` seen into
 * `helpers/base/push_data.h` file.
 */

/**
 * @brief This helper should be used to store signed 16 bit params.
 * The following types are compatible with this helper:
 * - PT_INT16
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param param param to store.
 */
static __always_inline void ringbuf__store_s16(struct ringbuf_struct *ringbuf, s16 param)
{
	PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, sizeof(s16));
}

/**
 * @brief This helper should be used to store signed 32 bit params.
 * The following types are compatible with this helper:
 * - PT_INT32
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param param param to store.
 */
static __always_inline void ringbuf__store_s32(struct ringbuf_struct *ringbuf, s32 param)
{
	PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, sizeof(s32));
}

/**
 * @brief This helper should be used to store signed 64 bit params.
 * The following types are compatible with this helper:
 * - PT_INT64
 * - PT_ERRNO
 * - PT_PID
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param param param to store
 */
static __always_inline void ringbuf__store_s64(struct ringbuf_struct *ringbuf, s64 param)
{
	PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, sizeof(s64));
}

/**
 * @brief This helper should be used to store unsigned 8 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT8
 * - PT_SIGTYPE
 * - PT_FLAGS8
 * - PT_ENUMFLAGS8
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param param param to store
 */
static __always_inline void ringbuf__store_u8(struct ringbuf_struct *ringbuf, u8 param)
{
	PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, sizeof(u8));
}

/**
 * @brief This helper should be used to store unsigned 16 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT16
 * - PT_FLAGS16
 * - PT_ENUMFLAGS16
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param param param to store
 */
static __always_inline void ringbuf__store_u16(struct ringbuf_struct *ringbuf, u16 param)
{
	PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, sizeof(u16));
}

/**
 * @brief This helper should be used to store unsigned 32 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT32
 * - PT_UID
 * - PT_GID
 * - PT_SIGSET
 * - PT_MODE
 * - PT_FLAGS32
 * - PT_ENUMFLAGS32
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param param param to store
 */
static __always_inline void ringbuf__store_u32(struct ringbuf_struct *ringbuf, u32 param)
{
	PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, sizeof(u32));
}

/**
 * @brief This helper should be used to store unsigned 64 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT64
 * - PT_RELTIME
 * - PT_ABSTIME
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param param param to store
 */
static __always_inline void ringbuf__store_u64(struct ringbuf_struct *ringbuf, u64 param)
{
	PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, sizeof(u64));
}
