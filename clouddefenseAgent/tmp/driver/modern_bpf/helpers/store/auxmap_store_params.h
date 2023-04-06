/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/base/push_data.h>
#include <helpers/extract/extract_from_kernel.h>

/*=============================== FIXED CONSTRAINTS ===============================*/

/* These are some of the constraints we want to impose during our
 * store operations. One day these could become const global variables
 * that could be set by the userspace.
 */

/* Right now a `cgroup` pathname can have at most 6 components. */
#define MAX_CGROUP_PATH_POINTERS 6

/* Right now a file path extracted from a file descriptor can
 * have at most `MAX_PATH_POINTERS` components.
 */
#define MAX_PATH_POINTERS 8

/* Maximum length of `unix` socket path.
 * We can have a maximum of 108 characters plus the `\0` terminator.
 */
#define MAX_UNIX_SOCKET_PATH 108 + 1

/* Maximum number of `iovec` structures that we can analyze. */
#define MAX_IOVCNT 32

/* Maximum number of `pollfd` structures that we can analyze. */
#define MAX_POLLFD 16

/* Maximum number of charbuf pointers that we assume an array can have. */
#define MAX_CHARBUF_POINTERS 16

/* Proc name */
#define MAX_PROC_EXE 4096

/* Proc arguments or environment variables.
 * Must be always a power of 2 because we can also use it as a mask!
 */
#define MAX_PROC_ARG_ENV 4096

/* PATH_MAX supported by the operating system: 4096 */
#define MAX_PATH 4096

/*=============================== FIXED CONSTRAINTS ===============================*/

/*=============================== COMMON DEFINITIONS ===============================*/

/* Some auxiliary definitions we use during our store operations */

/* Conversion factors used in `setsockopt` val. */
#define SEC_FACTOR 1000000000
#define USEC_FACTOR 1000

/* Network components size. */
#define FAMILY_SIZE sizeof(u8)
#define IPV4_SIZE sizeof(u32)
#define IPV6_SIZE 16
#define PORT_SIZE sizeof(u16)
#define KERNEL_POINTER sizeof(u64)

/* This enum is used to tell network helpers if the connection outbound
 * or inbound
 */
enum connection_direction
{
	OUTBOUND = 0,
	INBOUND = 1,
};

/* This enum is used to tell poll helpers if we need requested or returned
 * events.
 */
enum poll_events_direction
{
	REQUESTED_EVENTS = 0,
	RETURNED_EVENTS = 1,
};

/*=============================== COMMON DEFINITIONS ===============================*/

/* Concept of auxamp (auxiliary map):
 *
 * For variable size events we cannot directly reserve space into the ringbuf,
 * we need to use a bpf map as a temporary buffer to save our events. So every cpu
 * can use this temporary space when it receives a variable size event.
 *
 * This temporary space is represented as an `auxiliary map struct`. In
 * addition to the raw space (`data`) where we will save our event, there
 * are 2 integers placeholders that help us to understand in which part of
 * the buffer we are writing.
 *
 * struct auxiliary_map
 * {
 *	  u8 data[AUXILIARY_MAP_SIZE]; // raw space to save our variable-size event.
 *	  uint64_t payload_pos;	         // position of the first empty byte in the `data` buf.
 *	  uint8_t lengths_pos;	         // position the first empty slot into the lengths array of the event.
 * };
 *
 * To better understand the two indexes `payload_pos` and `lengths_pos`
 * please see the description of the event format in
 * `helpers/base/push_data.h`
 *
 * Please note: The auxiliary map can contain events of at most 64 KB,
 * but the `AUXILIARY_MAP_SIZE` is 128 KB. We have chosen this
 * size to make the verifier understand that there will always be
 * 64 KB free for a new event parameter. This allow us to easily
 * write data into the map without many extra checks.
 *
 * Look at the macro `SAFE_ACCESS(x)` defined in `helpers/base/push_data.h`.
 * If `payload_pos` is lower than `MAX_PARAM_SIZE` we use this index to write
 * new bytes, otherwise we use `payload_pos & MAX_PARAM_SIZE` as index. So
 * the index will be always lower than `MAX_PARAM_SIZE`!
 *
 * Please note that in this last case we are actually overwriting our event!
 * Using `payload_pos & MAX_PARAM_SIZE` as index means that we have already
 * written at least `MAX_PARAM_SIZE` so we are overwriting our data. This is
 * not an issue! If we have already written more than `MAX_PARAM_SIZE`, the
 * event size will be surely greather than 64 KB, so at the end of the collection
 * phase the entire event will be discarded!
 */

/////////////////////////////////
// GET AUXILIARY MAP
////////////////////////////////

/**
 * @brief Get the auxiliary map pointer for the current CPU.
 *
 * @return pointer to the auxmap
 */
static __always_inline struct auxiliary_map *auxmap__get()
{
	return maps__get_auxiliary_map();
}

/////////////////////////////////
// STORE EVENT HEADER INTO THE AUXILIARY MAP
////////////////////////////////

/**
 * @brief Push the event header inside the auxiliary map.
 *
 * Please note: we call this method `preload` since we cannot completely fill the
 * event header. When we call this method we don't know yet the overall size of
 * the event, we discover it only at the end of the collection phase. We have
 * to use the `auxmap__finalize_event_header` to "finalize" the header, inserting
 * also the total event length.
 *
 * @param auxmap pointer to the auxmap in which we are writing our event header.
 * @param event_type This is the type of the event that we are writing into the map.
 */
static __always_inline void auxmap__preload_event_header(struct auxiliary_map *auxmap, u16 event_type)
{
	struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)auxmap->data;
	u8 nparams = maps__get_event_num_params(event_type);
	hdr->ts = maps__get_boot_time() + bpf_ktime_get_boot_ns();
	hdr->tid = bpf_get_current_pid_tgid() & 0xffffffff;
	hdr->type = event_type;
	hdr->nparams = nparams;
	auxmap->payload_pos = sizeof(struct ppm_evt_hdr) + nparams * sizeof(u16);
	auxmap->lengths_pos = sizeof(struct ppm_evt_hdr);
}

/**
 * @brief Finalize the header writing the overall event len.
 *
 * @param auxmap pointer to the auxmap in which we are writing our event header.
 */
static __always_inline void auxmap__finalize_event_header(struct auxiliary_map *auxmap)
{
	struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)auxmap->data;
	hdr->len = auxmap->payload_pos;
}

/////////////////////////////////
// COPY EVENT FROM AUXMAP TO RINGBUF
////////////////////////////////

/**
 * @brief Copy the entire event from the auxiliary map to bpf ringbuf.
 * If the event is correctly copied in the ringbuf we increments the number
 * of events sent to userspace, otherwise we increment the dropped events.
 *
 * @param auxmap pointer to the auxmap in which we have already written the entire event.
 */
static __always_inline void auxmap__submit_event(struct auxiliary_map *auxmap)
{

	struct ringbuf_map *rb = maps__get_ringbuf_map();
	if(!rb)
	{
		return;
	}

	struct counter_map *counter = maps__get_counter_map();
	if(!counter)
	{
		return;
	}

	/* This counts the event seen by the drivers even if they are dropped because the buffer is full. */
	counter->n_evts++;

	if(auxmap->payload_pos > MAX_EVENT_SIZE)
	{
		counter->n_drops_max_event_size++;
		return;
	}

	/* `BPF_RB_NO_WAKEUP` means that we don't send to userspace a notification
	 *  when a new event is in the buffer.
	 */
	int err = bpf_ringbuf_output(rb, auxmap->data, auxmap->payload_pos, BPF_RB_NO_WAKEUP);
	if(err)
	{
		counter->n_drops_buffer++;
	}
}

/////////////////////////////////
// STORE EVENT PARAMS INTO THE AUXILIARY MAP
////////////////////////////////

/* All these `auxmap__store_(x)_param` helpers have the task
 * to store a particular param inside the bpf auxiliary map.
 * Note: `push__` functions store only some bytes into the map
 * and increment the payload pos. To store an entire param
 * we could need one or more `push__` helpers and one final `push__param_len`
 * to save the overall param len into the `lengths_array` seen into
 * `helpers/base/push_data.h` file.
 */

/**
 * @brief This function must be used when we are not able to correctly
 * collect the param. We simply put the param length to 0 into the
 * `lengths_array` of the event, so the userspace can easely understand
 * that the param is empty.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 */
static __always_inline void auxmap__store_empty_param(struct auxiliary_map *auxmap)
{
	push__param_len(auxmap->data, &auxmap->lengths_pos, 0);
}

/**
 * @brief This helper should be used to store signed 32 bit params.
 * The following types are compatible with this helper:
 * - PT_INT32
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_s32_param(struct auxiliary_map *auxmap, s32 param)
{
	push__s32(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(s32));
}

/**
 * @brief This helper should be used to store signed 64 bit params.
 * The following types are compatible with this helper:
 * - PT_INT64
 * - PT_ERRNO
 * - PT_PID
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_s64_param(struct auxiliary_map *auxmap, s64 param)
{
	push__s64(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(s64));
}

/**
 * @brief This helper should be used to store unsigned 8 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT8
 * - PT_SIGTYPE
 * - PT_FLAGS8
 * - PT_ENUMFLAGS8
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_u8_param(struct auxiliary_map *auxmap, u8 param)
{
	push__u8(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u8));
}

/**
 * @brief This helper should be used to store unsigned 16 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT16
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_u16_param(struct auxiliary_map *auxmap, u16 param)
{
	push__u16(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u16));
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
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_u32_param(struct auxiliary_map *auxmap, u32 param)
{
	push__u32(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u32));
}

/**
 * @brief This helper should be used to store unsigned 64 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT64
 * - PT_RELTIME
 * - PT_ABSTIME
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_u64_param(struct auxiliary_map *auxmap, u64 param)
{
	push__u64(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u64));
}

/**
 * @brief This helper stores the charbuf pointed by `charbuf_pointer`
 * into the auxmap. We read until we find a `\0`, if the charbuf length
 * is greater than `len_to_read`, we read up to `len_to_read-1` bytes
 * and add the `\0`. For more details, look at the underlying
 * `push__charbuf` method
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param charbuf_pointer pointer to the charbuf to store.
 * @param len_to_read upper bound limit.
 * @param mem from which memory we need to read: user-space or kernel-space.
 * @return number of bytes read.
 */
static __always_inline u16 auxmap__store_charbuf_param(struct auxiliary_map *auxmap, unsigned long charbuf_pointer, u16 len_to_read, enum read_memory mem)
{
	u16 charbuf_len = 0;
	/* This check is just for performance reasons. Is useless to check
	 * `len_to_read > 0` here, since `len_to_read` is just the upper bound.
	 */
	if(charbuf_pointer)
	{
		charbuf_len = push__charbuf(auxmap->data, &auxmap->payload_pos, charbuf_pointer, len_to_read, mem);
	}
	/* If we are not able to push anything with `push__charbuf`
	 * `charbuf_len` will be equal to `0` so we will send an
	 * empty param to userspace.
	 */
	push__param_len(auxmap->data, &auxmap->lengths_pos, charbuf_len);
	return charbuf_len;
}

/**
 * @brief This helper stores the bytebuf pointed by `bytebuf_pointer`
 * into the auxmap. The bytebuf has a fixed len `len_to_read`. If we
 * are not able to read exactly `len_to_read` bytes we will push an
 * empty param in the map, so param_len=0.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param bytebuf_pointer pointer to the bytebuf to store.
 * @param len_to_read number of bytes to read.
 * @param mem from which memory we need to read: user-space or kernel-space.
 * @return number of bytes read.
 */
static __always_inline u16 auxmap__store_bytebuf_param(struct auxiliary_map *auxmap, unsigned long bytebuf_pointer, u16 len_to_read, enum read_memory mem)
{
	u16 bytebuf_len = 0;
	/* This check is just for performance reasons. */
	if(bytebuf_pointer && len_to_read > 0)
	{
		bytebuf_len = push__bytebuf(auxmap->data, &auxmap->payload_pos, bytebuf_pointer, len_to_read, mem);
	}
	/* If we are not able to push anything with `push__bytebuf`
	 * `bytebuf_len` will be equal to `0` so we will send an
	 * empty param to userspace.
	 */
	push__param_len(auxmap->data, &auxmap->lengths_pos, bytebuf_len);
	return bytebuf_len;
}

/**
 * @brief Use `auxmap__store_execve_exe` when you have to store the
 * `exe` name from an execve-family syscall.
 * By convention, `exe` is `argv[0]`, this is the reason why here we pass the `argv` array.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param array charbuf pointer array, obtained directly from the syscall (`argv`).
 */
static __always_inline void auxmap__store_execve_exe(struct auxiliary_map *auxmap, char **array)
{
	unsigned long charbuf_pointer = 0;
	u16 exe_len = 0;

	if(bpf_probe_read_user(&charbuf_pointer, sizeof(charbuf_pointer), &array[0]))
	{
		push__param_len(auxmap->data, &auxmap->lengths_pos, exe_len);
		return;
	}

	exe_len = push__charbuf(auxmap->data, &auxmap->payload_pos, charbuf_pointer, MAX_PROC_EXE, USER);
	push__param_len(auxmap->data, &auxmap->lengths_pos, exe_len);
}

/**
 * @brief Use `auxmap__store_execve_args` when you have to store
 * `argv` or `envp` params from an execve-family syscall.
 * You have to provide an index that states where to start
 * the charbuf collection. This is becuase with `argv` we want to avoid
 * the first param (`argv[0]`), since it is already collected with
 * `auxmap__store_execve_exe`.
 *
 * Please note: right now we assume that our arrays have no more
 * than `MAX_CHARBUF_POINTERS`
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param array charbuf pointer array, obtained directly from the syscall (`argv` or `envp`).
 * @param index position at which we start to collect our charbufs.
 */
static __always_inline void auxmap__store_execve_args(struct auxiliary_map *auxmap, char **array, u16 index)
{
	unsigned long charbuf_pointer = 0;
	u16 arg_len = 0;
	u16 total_len = 0;
	u64 initial_payload_pos = auxmap->payload_pos;

	for(; index < MAX_CHARBUF_POINTERS; ++index)
	{
		if(bpf_probe_read_user(&charbuf_pointer, sizeof(charbuf_pointer), &array[index]))
		{
			break;
		}
		arg_len = push__charbuf(auxmap->data, &auxmap->payload_pos, charbuf_pointer, MAX_PROC_ARG_ENV, USER);
		if(!arg_len)
		{
			break;
		}
		total_len += arg_len;
	}
	/* the sum of all env variables lengths should be `<= MAX_PROC_ARG_ENV` */
	total_len = total_len & (MAX_PROC_ARG_ENV - 1);
	auxmap->payload_pos = initial_payload_pos + total_len;
	push__param_len(auxmap->data, &auxmap->lengths_pos, total_len);
}

/**
 * @brief This helper stores the file path extracted from the `fd`.
 *
 * Please note: Kernel 5.10 introduced a new bpf_helper called `bpf_d_path`
 * to extract a file path starting from a file descriptor but it can be used only
 * with specific hooks:
 *
 * https://github.com/torvalds/linux/blob/e0dccc3b76fb35bb257b4118367a883073d7390e/kernel/trace/bpf_trace.c#L915-L929.
 *
 * So we need to do it by hand and this cause a limit in the max
 * path component that we can retrieve (MAX_PATH_POINTERS).
 *
 * This version of `auxmap__store_path_from_fd` works smooth on all
 * supported architectures: `s390x`, `ARM64`, `x86_64`.
 * The drawback is that due to its complexity we can catch at most
 * `MAX_PATH_POINTERS==8`.
 *
 * The previous version of this method was able to correctly catch paths
 * under different mount points, but not on `s390x` architecture, where
 * the userspace test `open_by_handle_atX_success_mp` failed.
 *
 * #@Andreagit97: reduce the complexity of this helper to allow the capture
 * of more path components, or enable only this version of the helper on `s390x`,
 * leaving the previous working version on `x86` and `aarch64` architectures.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param fd file descriptor from which we want to retrieve the file path.
 */
static __always_inline void auxmap__store_path_from_fd(struct auxiliary_map *auxmap, s32 fd)
{
	u16 total_size = 0;
	u8 path_components = 0;
	unsigned long path_pointers[MAX_PATH_POINTERS] = {0};
	struct file *f = extract__file_struct_from_fd(fd);
	if(!f)
	{
		push__param_len(auxmap->data, &auxmap->lengths_pos, total_size);
	}

	struct task_struct *t = get_current_task();
	struct dentry *file_dentry = BPF_CORE_READ(f, f_path.dentry);
	struct dentry *root_dentry = READ_TASK_FIELD(t, fs, root.dentry);
	struct vfsmount *original_mount = BPF_CORE_READ(f, f_path.mnt);
	struct mount *mnt = container_of(original_mount, struct mount, mnt);
	struct dentry *mount_dentry = BPF_CORE_READ(mnt, mnt.mnt_root);
	struct dentry *file_dentry_parent = NULL;
	struct mount *parent_mount = NULL;

	/* Here we store all the pointers, note that we don't take the pointer
	 * to the root so we will add it manually if it is necessary!
	 */
	for(int k = 0; k < MAX_PATH_POINTERS; ++k)
	{
		if(file_dentry == root_dentry)
		{
			break;
		}

		if(file_dentry == mount_dentry)
		{
			BPF_CORE_READ_INTO(&parent_mount, mnt, mnt_parent);
			BPF_CORE_READ_INTO(&file_dentry, mnt, mnt_mountpoint);
			mnt = parent_mount;
			BPF_CORE_READ_INTO(&mount_dentry, mnt, mnt.mnt_root);
			continue;
		}

		path_components++;
		BPF_CORE_READ_INTO(&path_pointers[k], file_dentry, d_name.name);
		BPF_CORE_READ_INTO(&file_dentry_parent, file_dentry, d_parent);
		file_dentry = file_dentry_parent;
	}

	/* Reconstruct the path in reverse, using previously collected pointers.
	 *
	 * 1. As a first thing, we have to add the root `/`.
	 *
	 * 2. When we read the string in BPF with `bpf_probe_read_str()` we always
	 * add the `\0` terminator. In this way, we will obtain something like this:
	 *
	 * - "path_1\0"
	 * - "path_2\0"
	 * - "file\0"
	 *
	 * So putting it all together:
	 *
	 * 	"/path_1\0path_2\0file\0"
	 *
	 * (Note that we added `/` manually so there is no `\0`)
	 *
	 * But we want to obtain something like this:
	 *
	 * 	"/path_1/path_2/file\0"
	 *
	 * To obtain it we can replace all `\0` with `/`, but in this way we
	 * obtain:
	 *
	 * 	"/path_1/path_2/file/"
	 *
	 * So we need to replace the last `/` with `\0`.
	 */

	/* 1. Push the root `/` */
	push__new_character(auxmap->data, &auxmap->payload_pos, '/');
	total_size += 1;

	for(int k = MAX_PATH_POINTERS - 1; k >= 0; --k)
	{
		if(path_pointers[k])
		{
			total_size += push__charbuf(auxmap->data, &auxmap->payload_pos, path_pointers[k], MAX_PARAM_SIZE, KERNEL);
			push__previous_character(auxmap->data, &auxmap->payload_pos, '/');
		}
	}

	/* Different cases:
	 * - `path_components==0` we have to add the last `\0`.
	 * - `path_components==1` we need to replace the last `/` with a `\0`.
	 * - `path_components>1` we need to replace the last `/` with a `\0`.
	 */
	if(path_components >= 1)
	{
		push__previous_character(auxmap->data, &auxmap->payload_pos, '\0');
	}
	else
	{
		push__new_character(auxmap->data, &auxmap->payload_pos, '\0');
		total_size += 1;
	}

	push__param_len(auxmap->data, &auxmap->lengths_pos, total_size);
}

/**
 * @brief Store sockaddr info taken from syscall parameters.
 * This helper doesn't have the concept of `outbound` and `inbound` connections
 * since we read from userspace sockaddr struct. We have no to extract
 * different data in the kernel according to the direction as in
 * `auxmap__store_socktuple_param`.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param sockaddr_pointer pointer to the sockaddr struct
 * @param addrlen overall length of the sockaddr struct
 */
static __always_inline void auxmap__store_sockaddr_param(struct auxiliary_map *auxmap, unsigned long sockaddr_pointer, u16 addrlen)
{
	u16 final_param_len = 0;

	/* We put the struct sockaddr in our auxmap, since we have to write other
	 * data in the map, we push this temporary information in the second half
	 * of the map (so in the second 64 KB), that will never be used unless the
	 * event is invalid (too big).
	 *
	 *
	 * Please note: we don't increment `payload pos` since we use this counter
	 * only when we write correct data into our map. Here we use this space
	 * as scratch, we won't push these extra data to userspace!
	 *
	 * AUXMAP:
	 *
	 * 						 first half of the
	 * 						  auxmap ends here
	 * 						   (first 64 KB)
	 * 								 |
	 * 								 v
	 * -----------------------------------
	 * |      |                      | X
	 * -----------------------------------
	 * 	 	  ^                        ^
	 *        |                        |
	 *		we are                  we save
	 *   writing here           here the sockaddr
	 *     our data                  struct
	 */

	/* If we are not able to save the sockaddr return an empty parameter. */
	if(bpf_probe_read_user((void *)&auxmap->data[MAX_PARAM_SIZE], SAFE_ACCESS(addrlen), (void *)sockaddr_pointer) || addrlen == 0)
	{
		push__param_len(auxmap->data, &auxmap->lengths_pos, 0);
		return;
	}

	/* Save the pointer to the sockaddr struct in the stack. */
	struct sockaddr *sockaddr = (struct sockaddr *)&auxmap->data[MAX_PARAM_SIZE];
	u16 socket_family = sockaddr->sa_family;

	switch(socket_family)
	{
	case AF_INET:
	{
		/* Map the user-provided address to a sockaddr_in. */
		struct sockaddr_in *sockaddr_in = (struct sockaddr_in *)sockaddr;

		/* Copy address and port into the stack. */
		u32 ipv4 = sockaddr_in->sin_addr.s_addr;
		u16 port = sockaddr_in->sin_port;

		/* Pack the sockaddr info:
		 * - socket family.
		 * - ipv4.
		 * - port.
		 */
		push__u8(auxmap->data, &auxmap->payload_pos, socket_family_to_scap(socket_family));
		push__u32(auxmap->data, &auxmap->payload_pos, ipv4);
		push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port));
		final_param_len = FAMILY_SIZE + IPV4_SIZE + PORT_SIZE;
		break;
	}

	case AF_INET6:
	{
		/* Map the user-provided address to a sockaddr_in6. */
		struct sockaddr_in6 *sockaddr_in6 = (struct sockaddr_in6 *)sockaddr;

		/* Copy address and port into the stack. */
		u32 ipv6[4] = {0, 0, 0, 0};
		__builtin_memcpy(&ipv6, sockaddr_in6->sin6_addr.in6_u.u6_addr32, 16);
		u16 port = sockaddr_in6->sin6_port;

		/* Pack the sockaddr info:
		 * - socket family.
		 * - dest_ipv6.
		 * - dest_port.
		 */
		push__u8(auxmap->data, &auxmap->payload_pos, socket_family_to_scap(socket_family));
		push__ipv6(auxmap->data, &auxmap->payload_pos, ipv6);
		push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port));
		final_param_len = FAMILY_SIZE + IPV6_SIZE + PORT_SIZE;
		break;
	}

	case AF_UNIX:
	{
		/* Map the user-provided address to a sockaddr_un. */
		struct sockaddr_un *sockaddr_un = (struct sockaddr_un *)sockaddr;

		/* Starting at `sockaddr_un` we have the socket family and after it
		 * the `sun_path`.
		 *
		 * Please note exceptions in the `sun_path`:
		 * Taken from: https://man7.org/linux/man-pages/man7/unix.7.html
		 *
		 * An `abstract socket address` is distinguished (from a
		 * pathname socket) by the fact that sun_path[0] is a null byte
		 * ('\0').
		 */

		/* Check the exact point in which we have to start reading our path. */
		unsigned long start_reading_point;
		/* We skip the two bytes of socket family. */
		char first_path_byte = *(char *)sockaddr_un->sun_path;
		if(first_path_byte == '\0')
		{
			/* This is an abstract socket address, we need to skip the initial `\0`. */
			start_reading_point = (unsigned long)sockaddr_un->sun_path + 1;
		}
		else
		{
			start_reading_point = (unsigned long)sockaddr_un->sun_path;
		}

		/* Pack the sockaddr info:
		 * - socket family.
		 * - socket_unix_path (sun_path).
		 */
		push__u8(auxmap->data, &auxmap->payload_pos, socket_family_to_scap(socket_family));
		u16 written_bytes = push__charbuf(auxmap->data, &auxmap->payload_pos, start_reading_point, MAX_UNIX_SOCKET_PATH, KERNEL);
		final_param_len = FAMILY_SIZE + written_bytes;
		break;
	}

	default:
		final_param_len = 0;
		break;
	}
	push__param_len(auxmap->data, &auxmap->lengths_pos, final_param_len);
}

/**
 * @brief Store socktuple info taken from kernel socket.
 * We prefer extracting data directly from the kernel to
 * obtain more precise information.
 *
 * Please note:
 * In outbound connections `local` is the src while `remote` is the dest.
 * In inbound connections vice versa.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param socket_fd socket from which we extract information about the tuple.
 * @param direction specifies the connection direction.
 */
static __always_inline void auxmap__store_socktuple_param(struct auxiliary_map *auxmap, u32 socket_fd, int direction)
{
	u16 final_param_len = 0;

	/* Get the socket family directly from the socket */
	u16 socket_family = 0;
	struct file *file = extract__file_struct_from_fd(socket_fd);
	struct socket *socket = BPF_CORE_READ(file, private_data);
	struct sock *sk = BPF_CORE_READ(socket, sk);
	BPF_CORE_READ_INTO(&socket_family, sk, __sk_common.skc_family);

	switch(socket_family)
	{
	case AF_INET:
	{

		struct inet_sock *inet = (struct inet_sock *)sk;

		u32 ipv4_local = 0;
		u16 port_local = 0;
		u32 ipv4_remote = 0;
		u16 port_remote = 0;
		BPF_CORE_READ_INTO(&ipv4_local, inet, inet_saddr);
		BPF_CORE_READ_INTO(&port_local, inet, inet_sport);
		BPF_CORE_READ_INTO(&ipv4_remote, sk, __sk_common.skc_daddr);
		BPF_CORE_READ_INTO(&port_remote, sk, __sk_common.skc_dport);

		/* Pack the tuple info:
		 * - socket family
		 * - src_ipv4
		 * - dest_ipv4
		 * - src_port
		 * - dest_port
		 */
		push__u8(auxmap->data, &auxmap->payload_pos, socket_family_to_scap(socket_family));

		if(direction == OUTBOUND)
		{
			push__u32(auxmap->data, &auxmap->payload_pos, ipv4_local);
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_local));
			push__u32(auxmap->data, &auxmap->payload_pos, ipv4_remote);
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_remote));
		}
		else
		{
			push__u32(auxmap->data, &auxmap->payload_pos, ipv4_remote);
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_remote));
			push__u32(auxmap->data, &auxmap->payload_pos, ipv4_local);
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_local));
		}

		final_param_len = FAMILY_SIZE + IPV4_SIZE + PORT_SIZE + IPV4_SIZE + PORT_SIZE;
		break;
	}

	case AF_INET6:
	{
		/* Map the user-provided address to a sockaddr_in6. */
		struct inet_sock *inet = (struct inet_sock *)sk;

		u32 ipv6_local[4] = {0, 0, 0, 0};
		u16 port_local = 0;
		u32 ipv6_remote[4] = {0, 0, 0, 0};
		u16 port_remote = 0;

		BPF_CORE_READ_INTO(&ipv6_local, inet, pinet6, saddr);
		BPF_CORE_READ_INTO(&port_local, inet, inet_sport);
		BPF_CORE_READ_INTO(&ipv6_remote, sk, __sk_common.skc_v6_daddr);
		BPF_CORE_READ_INTO(&port_remote, sk, __sk_common.skc_dport);

		/* Pack the tuple info:
		 * - socket family
		 * - src_ipv6
		 * - dest_ipv6
		 * - src_port
		 * - dest_port
		 */
		push__u8(auxmap->data, &auxmap->payload_pos, socket_family_to_scap(socket_family));

		if(direction == OUTBOUND)
		{
			push__ipv6(auxmap->data, &auxmap->payload_pos, ipv6_local);
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_local));
			push__ipv6(auxmap->data, &auxmap->payload_pos, ipv6_remote);
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_remote));
		}
		else
		{
			push__ipv6(auxmap->data, &auxmap->payload_pos, ipv6_remote);
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_remote));
			push__ipv6(auxmap->data, &auxmap->payload_pos, ipv6_local);
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_local));
		}
		final_param_len = FAMILY_SIZE + IPV6_SIZE + PORT_SIZE + IPV6_SIZE + PORT_SIZE;
		break;
	}

	case AF_UNIX:
	{
		struct unix_sock *socket_local = (struct unix_sock *)sk;
		struct unix_sock *socket_remote = (struct unix_sock *)BPF_CORE_READ(socket_local, peer);
		char *path = NULL;

		/* Pack the tuple info:
		 * - socket family.
		 * - dest OS pointer.
		 * - src OS pointer.
		 * - dest unix_path.
		 */
		push__u8(auxmap->data, &auxmap->payload_pos, socket_family_to_scap(socket_family));
		if(direction == OUTBOUND)
		{
			push__u64(auxmap->data, &auxmap->payload_pos, (u64)socket_remote);
			push__u64(auxmap->data, &auxmap->payload_pos, (u64)socket_local);
			path = BPF_CORE_READ(socket_remote, addr, name[0].sun_path);
		}
		else
		{
			push__u64(auxmap->data, &auxmap->payload_pos, (u64)socket_local);
			push__u64(auxmap->data, &auxmap->payload_pos, (u64)socket_remote);
			path = BPF_CORE_READ(socket_local, addr, name[0].sun_path);
		}

		unsigned long start_reading_point;
		/* We have to skip the two bytes of socket family. */
		char first_path_byte = *(char *)path;
		if(first_path_byte == '\0')
		{
			/* This is an abstract socket address, we need to skip the initial `\0`. */
			start_reading_point = (unsigned long)path + 1;
		}
		else
		{
			start_reading_point = (unsigned long)path;
		}

		u16 written_bytes = push__charbuf(auxmap->data, &auxmap->payload_pos, start_reading_point, MAX_UNIX_SOCKET_PATH, KERNEL);
		final_param_len = FAMILY_SIZE + KERNEL_POINTER + KERNEL_POINTER + written_bytes;
		break;
	}

	default:
		final_param_len = 0;
		break;
	}

	// if we are not able to catch correct programs we push an empty param.
	push__param_len(auxmap->data, &auxmap->lengths_pos, final_param_len);
}

/**
 * @brief Store a sockopt param. Right now used by `setsockopt` syscall.
 * A sockopt is a `PT_DYN` param composed of:
 * - 1 byte for a scap code that indicates the type of option.
 * - variable number of bytes according to the option involved (This is
 *   why this param is marked as `PT_DYN` in the event table).
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param level protocol level
 * @param optname type of option
 * @param option_len actual len of the option
 * @param optval pointer to the option value
 */
static __always_inline void auxmap__store_sockopt_param(struct auxiliary_map *auxmap, int level, int optname, u16 option_len, unsigned long optval)
{
	/* We use a signed int because in some case we have to convert it to a negative value. */
	s32 val32 = 0;
	u64 val64 = 0;
	struct __kernel_timex_timeval tv;
	u16 total_size_to_push = sizeof(u8); /* 1 byte for the PPM type. */

	/* Levels different from `SOL_SOCKET` are not supported
	 * right now.
	 */
	if(level != SOL_SOCKET)
	{
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_SOCKOPT_IDX_UNKNOWN);
		total_size_to_push += push__bytebuf(auxmap->data, &auxmap->payload_pos, optval, option_len, USER);
		push__param_len(auxmap->data, &auxmap->lengths_pos, total_size_to_push);
		return;
	}

	switch(optname)
	{

	case SO_ERROR:
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_SOCKOPT_IDX_ERRNO);
		bpf_probe_read_user((void *)&val32, sizeof(val32), (void *)optval);
		push__s64(auxmap->data, &auxmap->payload_pos, (s64)-val32);
		total_size_to_push += sizeof(s64);
		break;

	case SO_RCVTIMEO_OLD:
	case SO_RCVTIMEO_NEW:
	case SO_SNDTIMEO_OLD:
	case SO_SNDTIMEO_NEW:
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_SOCKOPT_IDX_TIMEVAL);
		bpf_probe_read_user((void *)&tv, bpf_core_type_size(struct __kernel_timex_timeval), (void *)optval);
		push__u64(auxmap->data, &auxmap->payload_pos, tv.tv_sec * SEC_FACTOR + tv.tv_usec * USEC_FACTOR);
		total_size_to_push += sizeof(u64);
		break;

	case SO_COOKIE:
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_SOCKOPT_IDX_UINT64);
		bpf_probe_read_user((void *)&val64, sizeof(val64), (void *)optval);
		push__u64(auxmap->data, &auxmap->payload_pos, val64);
		total_size_to_push += sizeof(u64);
		break;

	case SO_DEBUG:
	case SO_REUSEADDR:
	case SO_TYPE:
	case SO_DONTROUTE:
	case SO_BROADCAST:
	case SO_SNDBUF:
	case SO_RCVBUF:
	case SO_SNDBUFFORCE:
	case SO_RCVBUFFORCE:
	case SO_KEEPALIVE:
	case SO_OOBINLINE:
	case SO_NO_CHECK:
	case SO_PRIORITY:
	case SO_BSDCOMPAT:
	case SO_REUSEPORT:
	case SO_PASSCRED:
	case SO_RCVLOWAT:
	case SO_SNDLOWAT:
	case SO_SECURITY_AUTHENTICATION:
	case SO_SECURITY_ENCRYPTION_TRANSPORT:
	case SO_SECURITY_ENCRYPTION_NETWORK:
	case SO_BINDTODEVICE:
	case SO_DETACH_FILTER:
	case SO_TIMESTAMP:
	case SO_ACCEPTCONN:
	case SO_PEERSEC:
	case SO_PASSSEC:
	case SO_TIMESTAMPNS:
	case SO_MARK:
	case SO_TIMESTAMPING:
	case SO_PROTOCOL:
	case SO_DOMAIN:
	case SO_RXQ_OVFL:
	case SO_WIFI_STATUS:
	case SO_PEEK_OFF:
	case SO_NOFCS:
	case SO_LOCK_FILTER:
	case SO_SELECT_ERR_QUEUE:
	case SO_BUSY_POLL:
	case SO_MAX_PACING_RATE:
	case SO_BPF_EXTENSIONS:
	case SO_INCOMING_CPU:
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_SOCKOPT_IDX_UINT32);
		bpf_probe_read_user((void *)&val32, sizeof(val32), (void *)optval);
		push__u32(auxmap->data, &auxmap->payload_pos, val32);
		total_size_to_push += sizeof(u32);
		break;

	default:
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_SOCKOPT_IDX_UNKNOWN);
		total_size_to_push += push__bytebuf(auxmap->data, &auxmap->payload_pos, optval, option_len, USER);
		break;
	}

	push__param_len(auxmap->data, &auxmap->lengths_pos, total_size_to_push);
}

/**
 * @brief Store the size of an iovec message.
 * Please note: the size is an unsigned 32 bit value so
 * internally this helper use the `auxmap__store_u32_param()`
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param msghdr_pointer pointer to `user_msghdr` struct.
 */
static __always_inline void auxmap__store_iovec_size_param(struct auxiliary_map *auxmap, unsigned long msghdr_pointer)
{
	/* Read the usr_msghdr struct into the stack, if we fail,
	 * we return an empty param.
	 */
	u32 total_size_to_read = 0;
	struct user_msghdr msghdr = {0};
	if(bpf_probe_read_user((void *)&msghdr, bpf_core_type_size(struct user_msghdr), (void *)msghdr_pointer))
	{
		auxmap__store_u32_param(auxmap, total_size_to_read);
		return;
	}

	u32 total_iovec_size = msghdr.msg_iovlen * bpf_core_type_size(struct iovec);

	/* We store all the data into the second part of our auxmap
	 * like in `auxmap__store_sockaddr_param`. This is a scratch space.
	 */
	if(bpf_probe_read_user((void *)&auxmap->data[MAX_PARAM_SIZE],
			       SAFE_ACCESS(total_iovec_size),
			       (void *)msghdr.msg_iov))
	{
		auxmap__store_u32_param(auxmap, total_size_to_read);
		return;
	}

	/* Pointer to iovec structs */
	const struct iovec *iovec = (const struct iovec *)&auxmap->data[MAX_PARAM_SIZE];
	for(int j = 0; j < MAX_IOVCNT; j++)
	{
		if(j == msghdr.msg_iovlen)
		{
			break;
		}
		total_size_to_read += iovec[j].iov_len;
	}
	auxmap__store_u32_param(auxmap, total_size_to_read);
}

/**
 * @brief Store data extracted from iovec structs.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param iov_pointer pointer to `iovec` struct.
 * @param iov_cnt number of iovec structs to be read from userspace.
 * @param len_to_read imposed snaplen.
 */
static __always_inline void auxmap__store_iovec_data_param(struct auxiliary_map *auxmap, unsigned long iov_pointer, unsigned long iov_cnt, unsigned long len_to_read)
{
	u32 total_size_to_read = 0;
	u32 total_iovec_size = iov_cnt * bpf_core_type_size(struct iovec);

	/* We store all the data into the second part of our auxmap
	 * like in `auxmap__store_sockaddr_param`. This is a scratch space.
	 */
	if(bpf_probe_read_user((void *)&auxmap->data[MAX_PARAM_SIZE],
			       SAFE_ACCESS(total_iovec_size),
			       (void *)iov_pointer))
	{
		/* in case of NULL iovec vector we return an empty param */
		push__param_len(auxmap->data, &auxmap->lengths_pos, 0);
		return;
	}

	/* Pointer to iovec structs */
	const struct iovec *iovec = (const struct iovec *)&auxmap->data[MAX_PARAM_SIZE];
	u64 initial_payload_pos = auxmap->payload_pos;
	for(int j = 0; j < MAX_IOVCNT; j++)
	{
		if(total_size_to_read > len_to_read)
		{
			/* If we break here it could be that `payload_pos` overcame the max `len_to_read` for this reason
			 * we have an enforcement after the for loop.
			 */
			total_size_to_read = len_to_read;
			break;
		}

		if(j == iov_cnt)
		{
			break;
		}

		u16 bytes_read = push__bytebuf(auxmap->data, &auxmap->payload_pos, (unsigned long)iovec[j].iov_base, iovec[j].iov_len, USER);
		if(!bytes_read)
		{
			push__param_len(auxmap->data, &auxmap->lengths_pos, total_size_to_read);
			return;
		}
		total_size_to_read += bytes_read;
	}
	/* We need this enforcement to be sure that we don't overcome the max `len_to_read` */
	auxmap->payload_pos = initial_payload_pos + total_size_to_read;
	push__param_len(auxmap->data, &auxmap->lengths_pos, total_size_to_read);
}

/**
 * @brief Store a message extracted from iovec structs.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param msghdr_pointer pointer to `user_msghdr` struct.
 * @param len_to_read imposed snaplen.
 */
static __always_inline void auxmap__store_msghdr_iovec_data_param(struct auxiliary_map *auxmap, unsigned long msghdr_pointer, unsigned long len_to_read)
{
	/* Read the usr_msghdr struct into the stack, if we fail,
	 * we return an empty param.
	 */
	struct user_msghdr msghdr = {0};
	if(bpf_probe_read_user((void *)&msghdr, bpf_core_type_size(struct user_msghdr), (void *)msghdr_pointer))
	{
		/* in case of NULL msghdr we return an empty param */
		push__param_len(auxmap->data, &auxmap->lengths_pos, 0);
		return;
	}

	u32 iov_cnt = msghdr.msg_iovlen;

	auxmap__store_iovec_data_param(auxmap, (unsigned long)msghdr.msg_iov, iov_cnt, len_to_read);
}

/**
 * @brief Store ptrace addr param. This helper is used by ptrace syscall.
 *  This param is of type `PT_DYN` and it is composed of:
 * - 1 byte: a scap code that indicates how the ptrace addr param is sent to userspace.
 *   As in the old probe we send only params of type `PPM_PTRACE_IDX_UINT64`.
 * - 8 byte: the ptrace addr value sent as a `PT_UINT64`.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param ret return value to understand which action we have to perform.
 * @param addr_pointer pointer to the `addr` param taken from syscall registers.
 */
static __always_inline void auxmap__store_ptrace_addr_param(struct auxiliary_map *auxmap, long ret, u64 addr_pointer)
{
	push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_UINT64);

	/* The syscall is failed. */
	if(ret < 0)
	{
		/* We push `0` in case of failure. */
		push__u64(auxmap->data, &auxmap->payload_pos, 0);
	}
	else
	{
		/* We send the addr pointer as a uint64_t */
		push__u64(auxmap->data, &auxmap->payload_pos, addr_pointer);
	}
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u8) + sizeof(u64));
}

/**
 * @brief Store ptrace data param. This helper is used by ptrace syscall.
 *  This param is of type `PT_DYN` and it is composed of:
 * - 1 byte: a scap code that indicates how the ptrace data param is sent to userspace.
 * - a variable size part according to the `ptrace_req`
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param ret return value to understand which action we have to perform.
 * @param ptrace_req ptrace request converted in the scap format.
 * @param data_pointer pointer to the `data` param taken from syscall registers.
 */
static __always_inline void auxmap__store_ptrace_data_param(struct auxiliary_map *auxmap, long ret, u16 ptrace_req, u64 data_pointer)
{
	/* The syscall is failed. */
	if(ret < 0)
	{
		/* We push `0` in case of failure. */
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_UINT64);
		push__u64(auxmap->data, &auxmap->payload_pos, 0);
		push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u8) + sizeof(u64));
		return;
	}

	u64 dest = 0;
	u16 total_size_to_push = sizeof(u8); /* 1 byte for the PPM type. */
	switch(ptrace_req)
	{
	case PPM_PTRACE_PEEKTEXT:
	case PPM_PTRACE_PEEKDATA:
	case PPM_PTRACE_PEEKUSR:
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_UINT64);
		bpf_probe_read_user((void *)&dest, sizeof(dest), (void *)data_pointer);
		push__u64(auxmap->data, &auxmap->payload_pos, dest);
		total_size_to_push += sizeof(u64);
		break;

	case PPM_PTRACE_CONT:
	case PPM_PTRACE_SINGLESTEP:
	case PPM_PTRACE_DETACH:
	case PPM_PTRACE_SYSCALL:
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_SIGTYPE);
		push__u8(auxmap->data, &auxmap->payload_pos, data_pointer);
		total_size_to_push += sizeof(u8);
		break;

	case PPM_PTRACE_ATTACH:
	case PPM_PTRACE_TRACEME:
	case PPM_PTRACE_POKETEXT:
	case PPM_PTRACE_POKEDATA:
	case PPM_PTRACE_POKEUSR:
	default:
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_UINT64);
		push__u64(auxmap->data, &auxmap->payload_pos, data_pointer);
		total_size_to_push += sizeof(u64);
		break;
	}
	push__param_len(auxmap->data, &auxmap->lengths_pos, total_size_to_push);
}

/**
 * @brief Store in the auxamp all data relative to a particular
 * `cgroup` subsystem. Data are stored in the following format:
 *
 * `cgroup_subsys_name=cgroup_path`
 *
 * Please note: This function is used only internally by `auxmap__store_cgroups_param`.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param task pointer to the current task struct.
 * @param cgrp_sub_id enum taken from vmlinux `cgroup_subsys_id`.
 * @return total len written in the aux map for this `cgroup` subsystem.
 */
static __always_inline u16 store_cgroup_subsys(struct auxiliary_map *auxmap, struct task_struct *task, enum cgroup_subsys_id cgrp_sub_id)
{
	u16 total_size = 0;

	/* Write cgroup subsystem name + '=' into the aux map (example "cpuset="). */
	const char *cgroup_subsys_name_ptr;
	BPF_CORE_READ_INTO(&cgroup_subsys_name_ptr, task, cgroups, subsys[cgrp_sub_id], ss, name);
	/* This could be 0.*/
	total_size += push__charbuf(auxmap->data, &auxmap->payload_pos, (unsigned long)cgroup_subsys_name_ptr, MAX_PARAM_SIZE, KERNEL);
	if(!total_size)
	{
		return 0;
	}
	/* In BPF all strings are ended with `\0` so here we overwrite the
	 * `\0` at the end of the `cgroup` name with `=`.
	 */
	push__previous_character(auxmap->data, &auxmap->payload_pos, '=');

	/* Read all pointers to the path components. */
	struct kernfs_node *kn;
	BPF_CORE_READ_INTO(&kn, task, cgroups, subsys[cgrp_sub_id], cgroup, kn);
	unsigned long cgroup_path_pointers[MAX_CGROUP_PATH_POINTERS] = {0};
	u8 path_components = 0;

	for(int k = 0; k < MAX_CGROUP_PATH_POINTERS; ++k)
	{
		if(!kn)
		{
			break;
		}
		path_components++;
		BPF_CORE_READ_INTO(&cgroup_path_pointers[k], kn, name);
		BPF_CORE_READ_INTO(&kn, kn, parent);
	}

	/* Reconstruct the path in reverse, using previously collected pointers.
	 * The first component we face must be the root "/". Unfortunately,
	 * when we read the root component from `struct kernfs_node` we
	 * obtain only "\0" instead of "/\0" (NOTE: \0 is always present
	 * at the end of the string, reading with `bpf_probe_read_str()`).
	 *
	 * The rationale here is to replace the string terminator '\0'
	 * with the '/' for every path compotent, excluding the last.
	 *
	 * Starting from what we have already inserted ("cpuset="),
	 * we want to obtain as a final result:
	 *
	 *  cpuset=/path_part1/path_part2\0
	 *
	 * Without replacing with '/', we would obtain this:
	 *
	 *  cpuset=\0path_part1\0path_part2\0
	 *
	 * Replacing all '\0' with '/':
	 *
	 *  cpuset=/path_part1/path_part2/
	 *
	 * As a last step we want to replace the last `/` with
	 * again the string terminator `\0`, finally obtaining:
	 *
	 *  cpuset=/path_part1/path_part2\0
	 */
	for(int k = MAX_CGROUP_PATH_POINTERS - 1; k >= 0; --k)
	{
		if(cgroup_path_pointers[k])
		{
			total_size += push__charbuf(auxmap->data, &auxmap->payload_pos, cgroup_path_pointers[k], MAX_PARAM_SIZE, KERNEL);
			push__previous_character(auxmap->data, &auxmap->payload_pos, '/');
		}
	}

	/* As a result of this for loop we can have three cases:
	 *
	 *  1. cpuset=/path_part1/path_part2/
	 *
	 *  2. cpuset=/ (please note: the '/' is correct but we miss the final '\0')
	 *
	 *  3. cpuset= (path_components=0)
	 *
	 * So according to the case we have to perform different actions:
	 *
	 *  1. cpuset=/path_part1/path_part2\0 (overwrite last '/' with '\0').
	 *
	 *  2. cpuset=/\0 (add the terminator char).
	 *
	 *  3. cpuset=\0 (add the terminator char)
	 *
	 * We can treat the `2` and the `3` in the same way, adding a char terminator at the end.
	 */
	if(path_components <= 1)
	{
		push__new_character(auxmap->data, &auxmap->payload_pos, '\0');
		total_size += 1;
	}
	else
	{
		push__previous_character(auxmap->data, &auxmap->payload_pos, '\0');
	}

	return total_size;
}

/**
 * @brief Store in the auxamp all the `cgroup` subsystems currently supported:
 * - cpuset_cgrp_id
 * - cpu_cgrp_id
 * - cpuacct_cgrp_id
 * - io_cgrp_id
 * - memory_cgrp_id
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param task pointer to the current task struct.
 */
static __always_inline void auxmap__store_cgroups_param(struct auxiliary_map *auxmap, struct task_struct *task)
{
	uint16_t total_croups_len = 0;
	if(bpf_core_enum_value_exists(enum cgroup_subsys_id, cpuset_cgrp_id))
	{
		total_croups_len += store_cgroup_subsys(auxmap, task, bpf_core_enum_value(enum cgroup_subsys_id, cpuset_cgrp_id));
	}
	if(bpf_core_enum_value_exists(enum cgroup_subsys_id, cpu_cgrp_id))
	{
		total_croups_len += store_cgroup_subsys(auxmap, task, bpf_core_enum_value(enum cgroup_subsys_id, cpu_cgrp_id));
	}
	if(bpf_core_enum_value_exists(enum cgroup_subsys_id, cpuacct_cgrp_id))
	{
		total_croups_len += store_cgroup_subsys(auxmap, task, bpf_core_enum_value(enum cgroup_subsys_id, cpuacct_cgrp_id));
	}
	if(bpf_core_enum_value_exists(enum cgroup_subsys_id, io_cgrp_id))
	{
		total_croups_len += store_cgroup_subsys(auxmap, task, bpf_core_enum_value(enum cgroup_subsys_id, io_cgrp_id));
	}
	if(bpf_core_enum_value_exists(enum cgroup_subsys_id, memory_cgrp_id))
	{
		total_croups_len += store_cgroup_subsys(auxmap, task, bpf_core_enum_value(enum cgroup_subsys_id, memory_cgrp_id));
	}
	push__param_len(auxmap->data, &auxmap->lengths_pos, total_croups_len);
}

static __always_inline void auxmap__store_fdlist_param(struct auxiliary_map *auxmap, unsigned long fds_pointer, u32 nfds, enum poll_events_direction dir)
{
	/* In this helper we push data in this format:
	 *  - number of `fd + flags` pairs  -> (u16)
	 *  - first pair (`fd + flags`)     -> (s64 + s16)
	 *  - second pair (`fd + flags`)    -> (s64 + s16)
	 *  - ...
	 *
	 * If `fds_pointer` is NULL we push just a pair's number equal to `0`
	 */

	/* We store all the struct's array in the second part of our auxmap
	 * like in `auxmap__store_sockaddr_param`. This is a scratch space.
	 */
	u32 structs_size = nfds * bpf_core_type_size(struct pollfd);
	if(bpf_probe_read_user((void *)&auxmap->data[MAX_PARAM_SIZE],
			       SAFE_ACCESS(structs_size),
			       (void *)fds_pointer))
	{
		/* pair's number equal to `0` */
		auxmap__store_u16_param(auxmap, 0);
		return;
	}

	/* The pair's number is equal to `nfds` if it is `<=MAX_POLLFD` otherwise it is `MAX_POLLFD` */
	u32 num_pairs = nfds <= MAX_POLLFD ? nfds : MAX_POLLFD;
	push__u16(auxmap->data, &auxmap->payload_pos, num_pairs);

	/* Pointer to `pollfd` structs */
	const struct pollfd *fds = (const struct pollfd *)&auxmap->data[MAX_PARAM_SIZE];

	/* For every `pollfd` struct we try to push an `fd` (s64) + `flags` (s16) */
	for(int j = 0; j < MAX_POLLFD; j++)
	{
		if(j == nfds)
		{
			break;
		}

		/* Push `fd` on 64 bit */
		push__s64(auxmap->data, &auxmap->payload_pos, (s64)fds[j].fd);

		/* Push `flags` according to the direction */
		if(dir == REQUESTED_EVENTS)
		{
			push__s16(auxmap->data, &auxmap->payload_pos, (s16)poll_events_to_scap(fds[j].events));
		}
		else
		{
			push__s16(auxmap->data, &auxmap->payload_pos, (s16)poll_events_to_scap(fds[j].revents));
		}
	}
	/* The param size is: 16 bit for the number of pairs + size of the pairs */
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u16) + (num_pairs * (sizeof(s64) + sizeof(s16))));
}
