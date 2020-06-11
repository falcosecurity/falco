/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __TYPES_H
#define __TYPES_H

#ifdef __KERNEL__

#define __bpf_section(NAME) __attribute__((section(NAME), used))

#define __always_inline inline __attribute__((always_inline))

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
#define TP_NAME "raw_tracepoint/"
#else
#define TP_NAME "tracepoint/"
#endif

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
struct sys_enter_args {
	unsigned long regs;
	unsigned long id;
};
#else
struct sys_enter_args {
	__u64 pad;
	long id;
	unsigned long args[6];
};
#endif

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
struct sys_exit_args {
	unsigned long regs;
	unsigned long ret;
};
#else
struct sys_exit_args {
	__u64 pad;
	long id;
	long ret;
};
#endif

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
struct sched_process_exit_args {
	unsigned long p;
};
#else
struct sched_process_exit_args {
	__u64 pad;
	char comm[16];
	pid_t pid;
	int prio;
};
#endif

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
struct sched_switch_args {
	unsigned long preempt;
	unsigned long prev;
	unsigned long next;
};
#else
struct sched_switch_args {
	__u64 pad;
	char prev_comm[TASK_COMM_LEN];
	pid_t prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[TASK_COMM_LEN];
	pid_t next_pid;
	int next_prio;
};
#endif

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
struct sched_process_fork_args {
	__u64 pad;
	char parent_comm[TASK_COMM_LEN];
	pid_t parent_pid;
	char child_comm[TASK_COMM_LEN];
	pid_t child_pid;
};
#endif

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
struct page_fault_args {
	unsigned long address;
	unsigned long regs;
	unsigned long error_code;
};
#else
struct page_fault_args {
	__u64 pad;
	unsigned long address;
	unsigned long ip;
	unsigned long error_code;
};
#endif

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
struct signal_deliver_args {
	unsigned long sig;
	unsigned long info;
	unsigned long ka;
};
#else
struct signal_deliver_args {
	__u64 pad;
	int sig;
	int errno;
	int code;
	unsigned long sa_handler;
	unsigned long sa_flags;
};
#endif

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
struct sys_stash_args {
	unsigned long args[6];
};
#endif

struct filler_data {
	void *ctx;
	struct sysdig_bpf_settings *settings;
	struct sysdig_bpf_per_cpu_state *state;
	char *tmp_scratch;
	const struct ppm_event_info *evt;
	const struct ppm_event_entry *filler_info;
	bool curarg_already_on_frame;
	char *buf;
#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
	unsigned long *args;
#endif
	int fd;
};

struct perf_event_header {
	__u32 type;
	__u16 misc;
	__u16 size;
};

struct perf_event_sample {
	struct perf_event_header header;
	__u32 size;
	char data[];
};

/*
 * Unfortunately the entire perf event length must fit in u16
 */
#define PERF_EVENT_MAX_SIZE (0xffff - sizeof(struct perf_event_sample))

/*
 * Due to the way the verifier works with accessing variable memory,
 * the scratch size needs to be at least 2^N > PERF_EVENT_MAX_SIZE * 2
 */
#define SCRATCH_SIZE (1 << 18)
#define SCRATCH_SIZE_MAX (SCRATCH_SIZE - 1)
#define SCRATCH_SIZE_HALF (SCRATCH_SIZE_MAX >> 1)

#endif /* __KERNEL__ */

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int inner_map_idx;
	unsigned int numa_node;
};

enum sysdig_map_types {
	SYSDIG_PERF_MAP = 0,
	SYSDIG_TAIL_MAP = 1,
	SYSDIG_SYSCALL_CODE_ROUTING_TABLE = 2,
	SYSDIG_SYSCALL_TABLE = 3,
	SYSDIG_EVENT_INFO_TABLE = 4,
	SYSDIG_FILLERS_TABLE = 5,
	SYSDIG_FRAME_SCRATCH_MAP = 6,
	SYSDIG_TMP_SCRATCH_MAP = 7,
	SYSDIG_SETTINGS_MAP = 8,
	SYSDIG_LOCAL_STATE_MAP = 9,
#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
	SYSDIG_STASH_MAP = 10,
#endif
};

struct sysdig_bpf_settings {
	uint64_t boot_time;
	void *socket_file_ops;
	uint32_t snaplen;
	uint32_t sampling_ratio;
	bool capture_enabled;
	bool do_dynamic_snaplen;
	bool page_faults;
	bool dropping_mode;
	bool is_dropping;
	bool tracers_enabled;
	uint16_t fullcapture_port_range_start;
	uint16_t fullcapture_port_range_end;
	uint16_t statsd_port;
} __attribute__((packed));

struct tail_context {
	enum ppm_event_type evt_type;
	unsigned long long ts;
	unsigned long curarg;
	unsigned long curoff;
	unsigned long len;
	int prev_res;
} __attribute__((packed));

struct sysdig_bpf_per_cpu_state {
	struct tail_context tail_ctx;
	unsigned long long n_evts;
	unsigned long long n_drops_buffer;
	unsigned long long n_drops_pf;
	unsigned long long n_drops_bug;
	unsigned int hotplug_cpu;
	bool in_use;
} __attribute__((packed));

#endif
