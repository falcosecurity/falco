/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef PPM_H_
#define PPM_H_


/*
 * Our Own ASSERT implementation, so we can easily switch among BUG_ON, WARN_ON and nothing
 */
#ifndef UDIG

#include <linux/time.h>

#ifdef _DEBUG
#define ASSERT(expr) WARN_ON(!(expr))
#else
#define ASSERT(expr)
#endif /* _DEBUG */

#endif /* UDIG */

#define RW_SNAPLEN_EVENT 4096
#define DPI_LOOKAHEAD_SIZE 16
#define PPM_NULL_RDEV MKDEV(1, 3)
#define PPM_PORT_MYSQL 3306
#define PPM_PORT_POSTGRES 5432
#define PPM_PORT_STATSD 8125
#define PPM_PORT_MONGODB 27017

typedef u64 nanoseconds;

/* This is an auxiliary struct we use in setsockopt
 * when `__kernel_timex_timeval` struct is not defined.
 */
struct __aux_timeval {
	long long int tv_sec;
	long long int tv_usec;
};

/*
 * The ring descriptor.
 * We have one of these for each CPU.
 */
struct ppm_ring_buffer_context {
	bool cpu_online;
	bool open;
	struct ppm_ring_buffer_info *info;
	char *buffer;
	nanoseconds last_print_time;
	u32 nevents;
#ifndef UDIG
	atomic_t preempt_count;
#endif	
	char *str_storage;	/* String storage. Size is one page. */
};

#ifndef UDIG
struct ppm_consumer_t {
	unsigned int id; // numeric id for the consumer (ie: registration index)
	struct task_struct *consumer_id;
#ifdef __percpu
	struct ppm_ring_buffer_context __percpu *ring_buffers;
#else
	struct ppm_ring_buffer_context *ring_buffers;
#endif
	u32 snaplen;
	u32 sampling_ratio;
	bool do_dynamic_snaplen;
	u32 sampling_interval;
	int is_dropping;
	int dropping_mode;
	volatile int need_to_insert_drop_e;
	volatile int need_to_insert_drop_x;
	struct list_head node;
	uint16_t fullcapture_port_range_start;
	uint16_t fullcapture_port_range_end;
	uint16_t statsd_port;
	unsigned long buffer_bytes_dim; /* Every consumer will have its per-CPU buffer dim in bytes. */
	DECLARE_BITMAP(syscalls_mask, SYSCALL_TABLE_SIZE);
	u32 tracepoints_attached;
};

typedef struct ppm_consumer_t ppm_consumer_t;
#endif // UDIG

#define STR_STORAGE_SIZE PAGE_SIZE

typedef unsigned long syscall_arg_t;

/*
 * Global functions
 *
 * These are analogous to get_user(), copy_from_user() and strncpy_from_user(),
 * but they can't sleep, barf on page fault or be preempted
 */
#define ppm_get_user(x, ptr) (ppm_copy_from_user(&x, ptr, sizeof(x)) ? -EFAULT : 0)
#ifndef UDIG
unsigned long ppm_copy_from_user(void *to, const void __user *from, unsigned long n);
long ppm_strncpy_from_user(char *to, const char __user *from, unsigned long n);
#endif // UDIG

/*
 * Global tables
 */

#ifdef CONFIG_MIPS
  #define SYSCALL_TABLE_ID0 __NR_Linux
#elif defined CONFIG_ARM
  #define SYSCALL_TABLE_ID0 __NR_SYSCALL_BASE
#elif defined CONFIG_X86 || defined CONFIG_SUPERH
  #define SYSCALL_TABLE_ID0 0
#elif defined CONFIG_PPC64
  #define SYSCALL_TABLE_ID0 0
#elif defined CONFIG_S390
  #define SYSCALL_TABLE_ID0 0
#elif defined CONFIG_ARM64
  #define SYSCALL_TABLE_ID0 0
#endif

extern const struct syscall_evt_pair g_syscall_table[];
extern const struct ppm_event_info g_event_info[];

#if defined(CONFIG_X86_64) && defined(CONFIG_IA32_EMULATION)
extern const struct syscall_evt_pair g_syscall_ia32_table[];
#endif

#ifndef UDIG
extern void ppm_syscall_get_arguments(struct task_struct *task, struct pt_regs *regs, unsigned long *args);
#endif

#define NS_TO_SEC(_ns) ((_ns) / 1000000000)
#define MORE_THAN_ONE_SECOND_AHEAD(_ns1, _ns2) ((_ns1) - (_ns2) > 1000000000)
#define SECOND_IN_NS 1000000000
#define USECOND_IN_NS 1000

#endif /* PPM_H_ */
