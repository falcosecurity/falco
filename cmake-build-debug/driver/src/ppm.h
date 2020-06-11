/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef PPM_H_
#define PPM_H_

#include <linux/version.h>

/*
 * Our Own ASSERT implementation, so we can easily switch among BUG_ON, WARN_ON and nothing
 */
#ifdef _DEBUG
#define ASSERT(expr) WARN_ON(!(expr))
#else
#define ASSERT(expr)
#endif

typedef u64 nanoseconds;

/*
 * Global defines
 */
#define CAPTURE_CONTEXT_SWITCHES
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32))
#define CAPTURE_SIGNAL_DELIVERIES
#endif
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 12, 0)) && defined(CONFIG_X86)
#define CAPTURE_PAGE_FAULTS
#endif
#define RW_SNAPLEN_EVENT 4096
#define DPI_LOOKAHEAD_SIZE 16
#define PPM_NULL_RDEV MKDEV(1, 3)
#define PPM_PORT_MYSQL 3306
#define PPM_PORT_POSTGRES 5432
#define PPM_PORT_STATSD 8125
#define PPM_PORT_MONGODB 27017

/*
 * The ring descriptor.
 * We have one of these for each CPU.
 */
struct ppm_ring_buffer_context {
	bool cpu_online;
	bool open;
	bool capture_enabled;
	struct ppm_ring_buffer_info *info;
	char *buffer;
	nanoseconds last_print_time;
	u32 nevents;
	atomic_t preempt_count;
	char *str_storage;	/* String storage. Size is one page. */
};

struct ppm_consumer_t {
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
};

#define STR_STORAGE_SIZE PAGE_SIZE

/*
 * Global functions
 *
 * These are analogous to get_user(), copy_from_user() and strncpy_from_user(),
 * but they can't sleep, barf on page fault or be preempted
 */
#define ppm_get_user(x, ptr) ({ ppm_copy_from_user(&x, ptr, sizeof(x)) ? -EFAULT : 0; })
unsigned long ppm_copy_from_user(void *to, const void __user *from, unsigned long n);
long ppm_strncpy_from_user(char *to, const char __user *from, unsigned long n);

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
#endif

extern const struct syscall_evt_pair g_syscall_table[];
extern const struct ppm_event_info g_event_info[];
extern const enum ppm_syscall_code g_syscall_code_routing_table[];

#if defined(CONFIG_X86_64) && defined(CONFIG_IA32_EMULATION)
extern const struct syscall_evt_pair g_syscall_ia32_table[];
extern const enum ppm_syscall_code g_syscall_ia32_code_routing_table[];
#endif

extern void ppm_syscall_get_arguments(struct task_struct *task, struct pt_regs *regs, unsigned long *args);

#define NS_TO_SEC(_ns) ((_ns) / 1000000000)
#define MORE_THAN_ONE_SECOND_AHEAD(_ns1, _ns2) ((_ns1) - (_ns2) > 1000000000)
#define SECOND_IN_NS 1000000000

#endif /* PPM_H_ */
