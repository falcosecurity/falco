/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20)
#include <linux/kobject.h>
#include <trace/sched.h>
#include "ppm_syscall.h"
#include <trace/syscall.h>
#else
#include <asm/syscall.h>
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37))
#include <asm/atomic.h>
#else
#include <linux/atomic.h>
#endif
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kdev_t.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0))
#include <linux/sched.h>
#else
#include <linux/sched/signal.h>
#include <linux/sched/cputime.h>
#endif
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/tracepoint.h>
#include <linux/cpu.h>
#include <linux/jiffies.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26))
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif
#include <net/sock.h>
#include <asm/unistd.h>

#include "driver_config.h"
#include "ppm_ringbuffer.h"
#include "ppm_events_public.h"
#include "ppm_events.h"
#include "ppm.h"
#if defined(CONFIG_IA32_EMULATION) && !defined(__NR_ia32_socketcall)
#include "ppm_compat_unistd_32.h"
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sysdig inc");

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
    #define TRACEPOINT_PROBE_REGISTER(p1, p2) tracepoint_probe_register(p1, p2)
    #define TRACEPOINT_PROBE_UNREGISTER(p1, p2) tracepoint_probe_unregister(p1, p2)
    #define TRACEPOINT_PROBE(probe, args...) static void probe(args)
#else
    #define TRACEPOINT_PROBE_REGISTER(p1, p2) tracepoint_probe_register(p1, p2, NULL)
    #define TRACEPOINT_PROBE_UNREGISTER(p1, p2) tracepoint_probe_unregister(p1, p2, NULL)
    #define TRACEPOINT_PROBE(probe, args...) static void probe(void *__data, args)
#endif

#ifndef pgprot_encrypted
#define pgprot_encrypted(x) (x)
#endif

struct ppm_device {
	dev_t dev;
	struct cdev cdev;
	wait_queue_head_t read_queue;
};

struct event_data_t {
	enum ppm_capture_category category;
	int socketcall_syscall;
	bool compat;

	union {
		struct {
			struct pt_regs *regs;
			long id;
			const enum ppm_syscall_code *cur_g_syscall_code_routing_table;
		} syscall_data;

		struct {
			struct task_struct *sched_prev;
			struct task_struct *sched_next;
		} context_data;

		struct {
			int sig;
			struct siginfo *info;
			struct k_sigaction *ka;
		} signal_data;

		struct fault_data_t fault_data;
	} event_info;
};

/*
 * FORWARD DECLARATIONS
 */
static int ppm_open(struct inode *inode, struct file *filp);
static int ppm_release(struct inode *inode, struct file *filp);
static long ppm_ioctl(struct file *f, unsigned int cmd, unsigned long arg);
static int ppm_mmap(struct file *filp, struct vm_area_struct *vma);
static int record_event_consumer(struct ppm_consumer_t *consumer,
                                 enum ppm_event_type event_type,
                                 enum syscall_flags drop_flags,
                                 nanoseconds ns,
                                 struct event_data_t *event_datap);
static void record_event_all_consumers(enum ppm_event_type event_type,
                                       enum syscall_flags drop_flags,
                                       struct event_data_t *event_datap);
static int init_ring_buffer(struct ppm_ring_buffer_context *ring);
static void free_ring_buffer(struct ppm_ring_buffer_context *ring);
static void reset_ring_buffer(struct ppm_ring_buffer_context *ring);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
void ppm_task_cputime_adjusted(struct task_struct *p, cputime_t *ut, cputime_t *st);
#endif

#ifndef CONFIG_HAVE_SYSCALL_TRACEPOINTS
 #error The kernel must have HAVE_SYSCALL_TRACEPOINTS in order for sysdig to be useful
#endif

TRACEPOINT_PROBE(syscall_enter_probe, struct pt_regs *regs, long id);
TRACEPOINT_PROBE(syscall_exit_probe, struct pt_regs *regs, long ret);
TRACEPOINT_PROBE(syscall_procexit_probe, struct task_struct *p);
#ifdef CAPTURE_CONTEXT_SWITCHES
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
TRACEPOINT_PROBE(sched_switch_probe, struct rq *rq, struct task_struct *prev, struct task_struct *next);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
TRACEPOINT_PROBE(sched_switch_probe, struct task_struct *prev, struct task_struct *next);
#else
TRACEPOINT_PROBE(sched_switch_probe, bool preempt, struct task_struct *prev, struct task_struct *next);
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)) */
#endif /* CAPTURE_CONTEXT_SWITCHES */

#ifdef CAPTURE_SIGNAL_DELIVERIES
TRACEPOINT_PROBE(signal_deliver_probe, int sig, struct siginfo *info, struct k_sigaction *ka);
#endif

#ifdef CAPTURE_PAGE_FAULTS
TRACEPOINT_PROBE(page_fault_probe, unsigned long address, struct pt_regs *regs, unsigned long error_code);
#endif

DECLARE_BITMAP(g_events_mask, PPM_EVENT_MAX);
static struct ppm_device *g_ppm_devs;
static struct class *g_ppm_class;
static unsigned int g_ppm_numdevs;
static int g_ppm_major;
bool g_tracers_enabled = false;
bool g_simple_mode_enabled = false;
static DEFINE_PER_CPU(long, g_n_tracepoint_hit);
static const struct file_operations g_ppm_fops = {
	.open = ppm_open,
	.release = ppm_release,
	.mmap = ppm_mmap,
	.unlocked_ioctl = ppm_ioctl,
	.owner = THIS_MODULE,
};

/*
 * GLOBALS
 */
LIST_HEAD(g_consumer_list);
static DEFINE_MUTEX(g_consumer_mutex);
static bool g_tracepoint_registered;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
static struct tracepoint *tp_sys_enter;
static struct tracepoint *tp_sys_exit;
#endif

static struct tracepoint *tp_sched_process_exit;
#ifdef CAPTURE_CONTEXT_SWITCHES
static struct tracepoint *tp_sched_switch;
#endif
#ifdef CAPTURE_SIGNAL_DELIVERIES
static struct tracepoint *tp_signal_deliver;
#endif
#ifdef CAPTURE_PAGE_FAULTS
// Even in kernels that can support page fault tracepoints, tracepoints may be
// disabled so check if g_fault_tracepoint_disabled is set.
static struct tracepoint *tp_page_fault_user;
static struct tracepoint *tp_page_fault_kernel;
static bool g_fault_tracepoint_registered;
static bool g_fault_tracepoint_disabled;
#endif

#ifdef _DEBUG
static bool verbose = 1;
#else
static bool verbose = 0;
#endif

static unsigned int max_consumers = 5;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0))
static enum cpuhp_state hp_state = 0;
#endif

#define vpr_info(fmt, ...)					\
do {								\
	if (verbose)						\
		pr_info(fmt, ##__VA_ARGS__);			\
} while (0)

static inline nanoseconds ppm_nsecs(void)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0))
	return ktime_get_real_ns();
#else
	/* Don't have ktime_get_real functions */
	struct timespec ts;
	getnstimeofday(&ts);
	return SECOND_IN_NS * ts.tv_sec + ts.tv_nsec;
#endif
}

inline void ppm_syscall_get_arguments(struct task_struct *task, struct pt_regs *regs, unsigned long *args)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0))
    syscall_get_arguments(task, regs, 0, 6, args);
#else
    syscall_get_arguments(task, regs, args);
#endif
}

/* compat tracepoint functions */
static int compat_register_trace(void *func, const char *probename, struct tracepoint *tp)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
	return TRACEPOINT_PROBE_REGISTER(probename, func);
#else
	return tracepoint_probe_register(tp, func, NULL);
#endif
}

static void compat_unregister_trace(void *func, const char *probename, struct tracepoint *tp)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
	TRACEPOINT_PROBE_UNREGISTER(probename, func);
#else
	tracepoint_probe_unregister(tp, func, NULL);
#endif
}

static struct ppm_consumer_t *ppm_find_consumer(struct task_struct *consumer_id)
{
	struct ppm_consumer_t *el = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(el, &g_consumer_list, node) {
		if (el->consumer_id == consumer_id) {
			rcu_read_unlock();
			return el;
		}
	}
	rcu_read_unlock();

	return NULL;
}

static void check_remove_consumer(struct ppm_consumer_t *consumer, int remove_from_list)
{
	int cpu;
	int open_rings = 0;

	for_each_possible_cpu(cpu) {
		struct ppm_ring_buffer_context *ring = per_cpu_ptr(consumer->ring_buffers, cpu);

		if (ring && ring->open)
			++open_rings;
	}

	if (open_rings == 0) {
		pr_info("deallocating consumer %p\n", consumer->consumer_id);

		if (remove_from_list) {
			list_del_rcu(&consumer->node);
			synchronize_rcu();
		}

		for_each_possible_cpu(cpu) {
			struct ppm_ring_buffer_context *ring = per_cpu_ptr(consumer->ring_buffers, cpu);
			free_ring_buffer(ring);
		}

		free_percpu(consumer->ring_buffers);

		vfree(consumer);
	}
}

/*
 * user I/O functions
 */
static int ppm_open(struct inode *inode, struct file *filp)
{
	int ret;
	int in_list = false;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	int ring_no = iminor(filp->f_path.dentry->d_inode);
#else
	int ring_no = iminor(filp->f_dentry->d_inode);
#endif
	struct task_struct *consumer_id = current;
	struct ppm_consumer_t *consumer = NULL;
	struct ppm_ring_buffer_context *ring = NULL;

	/*
	 * Tricky: to identify a consumer, attach the thread id
	 * to the newly open file descriptor
	 */
	filp->private_data = consumer_id;

	mutex_lock(&g_consumer_mutex);

	consumer = ppm_find_consumer(consumer_id);
	if (!consumer) {
		unsigned int cpu;
		unsigned int num_consumers = 0;
		struct ppm_consumer_t *el = NULL;

		rcu_read_lock();
		list_for_each_entry_rcu(el, &g_consumer_list, node) {
			++num_consumers;
		}
		rcu_read_unlock();

		if (num_consumers >= max_consumers) {
			pr_err("maximum number of consumers reached\n");
			ret = -EBUSY;
			goto cleanup_open;
		}

		pr_info("adding new consumer %p\n", consumer_id);

		consumer = vmalloc(sizeof(struct ppm_consumer_t));
		if (!consumer) {
			pr_err("can't allocate consumer\n");
			ret = -ENOMEM;
			goto cleanup_open;
		}

		consumer->consumer_id = consumer_id;

		/*
		 * Initialize the ring buffers array
		 */
		consumer->ring_buffers = alloc_percpu(struct ppm_ring_buffer_context);
		if (consumer->ring_buffers == NULL) {
			pr_err("can't allocate the ring buffer array\n");

			vfree(consumer);

			ret = -ENOMEM;
			goto cleanup_open;
		}

		/*
		 * Note, we have two loops here because the first one makes sure that ALL of the
		 * rings are properly initialized to null, since the second one could be interrupted
		 * and cause issues in the cleanup phase.
		 * This might not be necessary, because alloc_percpu memsets the allocated entries to
		 * 0, but better be extra safe.
		 */
		for_each_possible_cpu(cpu) {
			ring = per_cpu_ptr(consumer->ring_buffers, cpu);

			ring->cpu_online = false;
			ring->str_storage = NULL;
			ring->buffer = NULL;
			ring->info = NULL;
		}

		/*
		 * If a cpu is offline when the consumer is first created, we
		 * will never get events for that cpu even if it later comes
		 * online via hotplug. We could allocate these rings on-demand
		 * later in this function if needed for hotplug, but that
		 * requires the consumer to know to call open again, and sysdig
		 * doesn't support that.
		 */
		for_each_online_cpu(cpu) {
			ring = per_cpu_ptr(consumer->ring_buffers, cpu);

			pr_info("initializing ring buffer for CPU %u\n", cpu);

			if (!init_ring_buffer(ring)) {
				pr_err("can't initialize the ring buffer for CPU %u\n", cpu);
				ret = -ENOMEM;
				goto err_init_ring_buffer;
			}

			ring->cpu_online = true;
		}

		list_add_rcu(&consumer->node, &g_consumer_list);
		in_list = true;
	} else {
		vpr_info("found already existent consumer %p\n", consumer_id);
	}

	ring = per_cpu_ptr(consumer->ring_buffers, ring_no);

	/*
	 * Check if the CPU pointed by this device is online. If it isn't stop here and
	 * return ENODEV. The cpu could be online while buffer is NULL if there's a cpu
	 * online hotplug callback between the first open on this consumer and the open
	 * for this particular device.
	 */
	if (ring->cpu_online == false || ring->buffer == NULL) {
		ret = -ENODEV;
		goto cleanup_open;
	}

	if (ring->open) {
		pr_err("invalid operation: attempting to open device %d multiple times for consumer %p\n", ring_no, consumer->consumer_id);
		ret = -EBUSY;
		goto cleanup_open;
	}

	vpr_info("opening ring %d, consumer %p\n", ring_no, consumer->consumer_id);

	/*
	 * ring->preempt_count is not reset to 0 on purpose, to prevent a race condition:
	 * if the same device is quickly closed and then reopened, record_event() might still be executing
	 * (with ring->preempt_count to 1) while ppm_open() resets ring->preempt_count to 0.
	 * When record_event() will exit, it will decrease
	 * ring->preempt_count which will become < 0, leading to the complete loss of all the events for that CPU.
	 */
	consumer->dropping_mode = 0;
	consumer->snaplen = RW_SNAPLEN;
	consumer->sampling_ratio = 1;
	consumer->sampling_interval = 0;
	consumer->is_dropping = 0;
	consumer->do_dynamic_snaplen = false;
	consumer->need_to_insert_drop_e = 0;
	consumer->need_to_insert_drop_x = 0;
	consumer->fullcapture_port_range_start = 0;
	consumer->fullcapture_port_range_end = 0;
	consumer->statsd_port = PPM_PORT_STATSD;
	bitmap_fill(g_events_mask, PPM_EVENT_MAX); /* Enable all syscall to be passed to userspace */
	reset_ring_buffer(ring);
	ring->open = true;

	if (!g_tracepoint_registered) {
		pr_info("starting capture\n");
		/*
		 * Enable the tracepoints
		 */

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		ret = compat_register_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
#else
		ret = register_trace_syscall_exit(syscall_exit_probe);
#endif
		if (ret) {
			pr_err("can't create the sys_exit tracepoint\n");
			goto err_sys_exit;
		}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		ret = compat_register_trace(syscall_enter_probe, "sys_enter", tp_sys_enter);
#else
		ret = register_trace_syscall_enter(syscall_enter_probe);
#endif
		if (ret) {
			pr_err("can't create the sys_enter tracepoint\n");
			goto err_sys_enter;
		}

		ret = compat_register_trace(syscall_procexit_probe, "sched_process_exit", tp_sched_process_exit);
		if (ret) {
			pr_err("can't create the sched_process_exit tracepoint\n");
			goto err_sched_procexit;
		}

#ifdef CAPTURE_CONTEXT_SWITCHES
		ret = compat_register_trace(sched_switch_probe, "sched_switch", tp_sched_switch);
		if (ret) {
			pr_err("can't create the sched_switch tracepoint\n");
			goto err_sched_switch;
		}
#endif

#ifdef CAPTURE_SIGNAL_DELIVERIES
		ret = compat_register_trace(signal_deliver_probe, "signal_deliver", tp_signal_deliver);
		if (ret) {
			pr_err("can't create the signal_deliver tracepoint\n");
			goto err_signal_deliver;
		}
#endif
		g_tracepoint_registered = true;
	}

	ret = 0;

	goto cleanup_open;

#ifdef CAPTURE_SIGNAL_DELIVERIES
err_signal_deliver:
	compat_unregister_trace(sched_switch_probe, "sched_switch", tp_sched_switch);
#endif
err_sched_switch:
	compat_unregister_trace(syscall_procexit_probe, "sched_process_exit", tp_sched_process_exit);
err_sched_procexit:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	compat_unregister_trace(syscall_enter_probe, "sys_enter", tp_sys_enter);
#else
	unregister_trace_syscall_enter(syscall_enter_probe);
#endif
err_sys_enter:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	compat_unregister_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
#else
	unregister_trace_syscall_exit(syscall_exit_probe);
#endif
err_sys_exit:
	ring->open = false;
err_init_ring_buffer:
	check_remove_consumer(consumer, in_list);
cleanup_open:
	mutex_unlock(&g_consumer_mutex);

	return ret;
}

static int ppm_release(struct inode *inode, struct file *filp)
{
	int cpu;
	int ret;
	struct ppm_ring_buffer_context *ring;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	int ring_no = iminor(filp->f_path.dentry->d_inode);
#else
	int ring_no = iminor(filp->f_dentry->d_inode);
#endif
	struct task_struct *consumer_id = filp->private_data;
	struct ppm_consumer_t *consumer = NULL;

	mutex_lock(&g_consumer_mutex);

	consumer = ppm_find_consumer(consumer_id);
	if (!consumer) {
		pr_err("release: unknown consumer %p\n", consumer_id);
		ret = -EBUSY;
		goto cleanup_release;
	}

	ring = per_cpu_ptr(consumer->ring_buffers, ring_no);
	if (!ring) {
		ASSERT(false);
		ret = -ENODEV;
		goto cleanup_release;
	}

	if (!ring->open) {
		pr_err("attempting to close unopened device %d for consumer %p\n", ring_no, consumer_id);
		ret = -EBUSY;
		goto cleanup_release;
	}

	ring->capture_enabled = false;

	vpr_info("closing ring %d, consumer:%p evt:%llu, dr_buf:%llu, dr_pf:%llu, pr:%llu, cs:%llu\n",
	       ring_no,
	       consumer_id,
	       ring->info->n_evts,
	       ring->info->n_drops_buffer,
	       ring->info->n_drops_pf,
	       ring->info->n_preemptions,
	       ring->info->n_context_switches);

	ring->open = false;

	check_remove_consumer(consumer, true);

	/*
	 * The last closed device stops event collection
	 */
	if (list_empty(&g_consumer_list)) {
		if (g_tracepoint_registered) {
			pr_info("no more consumers, stopping capture\n");

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
			compat_unregister_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
			compat_unregister_trace(syscall_enter_probe, "sys_enter", tp_sys_enter);
#else
			unregister_trace_syscall_exit(syscall_exit_probe);
			unregister_trace_syscall_enter(syscall_enter_probe);
#endif
			compat_unregister_trace(syscall_procexit_probe, "sched_process_exit", tp_sched_process_exit);

#ifdef CAPTURE_CONTEXT_SWITCHES
			compat_unregister_trace(sched_switch_probe, "sched_switch", tp_sched_switch);
#endif
#ifdef CAPTURE_SIGNAL_DELIVERIES
			compat_unregister_trace(signal_deliver_probe, "signal_deliver", tp_signal_deliver);
#endif
#ifdef CAPTURE_PAGE_FAULTS
			if (g_fault_tracepoint_registered) {
				compat_unregister_trace(page_fault_probe, "page_fault_user", tp_page_fault_user);
				compat_unregister_trace(page_fault_probe, "page_fault_kernel", tp_page_fault_kernel);

				g_fault_tracepoint_registered = false;
			}
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
			tracepoint_synchronize_unregister();
#endif
			g_tracepoint_registered = false;

			/*
			 * While we're here, disable simple mode if it's active
			 */
			g_simple_mode_enabled = false;

			/*
			 * Reset tracepoint counter
			 */
			for_each_possible_cpu(cpu) {
				per_cpu(g_n_tracepoint_hit, cpu) = 0;
			}
		} else {
			ASSERT(false);
		}
	}

	ret = 0;

cleanup_release:
	mutex_unlock(&g_consumer_mutex);

	return ret;
}

static long ppm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int cpu;
	int ret;
	struct task_struct *consumer_id = filp->private_data;
	struct ppm_consumer_t *consumer = NULL;

	if (cmd == PPM_IOCTL_GET_PROCLIST) {
		struct ppm_proclist_info *proclist_info = NULL;
		struct task_struct *p, *t;
		u64 nentries = 0;
		struct ppm_proclist_info pli;
		u32 memsize;

		if (copy_from_user(&pli, (void *)arg, sizeof(pli))) {
			ret = -EINVAL;
			goto cleanup_ioctl_nolock;
		}

		if(pli.max_entries < 0 || pli.max_entries > 1000000)
		{
			vpr_info("PPM_IOCTL_GET_PROCLIST: invalid max_entries %llu\n", pli.max_entries);
			ret = -EINVAL;
			goto cleanup_ioctl_procinfo;
		}

		vpr_info("PPM_IOCTL_GET_PROCLIST, size=%d\n", (int)pli.max_entries);

		memsize = sizeof(struct ppm_proclist_info) + sizeof(struct ppm_proc_info) * pli.max_entries;
		proclist_info = vmalloc(memsize);
		if (!proclist_info) {
			ret = -EINVAL;
			goto cleanup_ioctl_nolock;
		}

		proclist_info->max_entries = pli.max_entries;

		rcu_read_lock();

#ifdef for_each_process_thread
		for_each_process_thread(p, t) {
#else
#ifdef for_each_process_all
		for_each_process_all(p) {
#else
		for_each_process(p) {
#endif
			t = p;
			do {
				task_lock(p);
#endif
				if (nentries < pli.max_entries) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0))
					cputime_t utime, stime;
#else
					u64 utime, stime;
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0))
					task_cputime_adjusted(t, &utime, &stime);
#else
					ppm_task_cputime_adjusted(t, &utime, &stime);
#endif
					proclist_info->entries[nentries].pid = t->pid;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0))
					proclist_info->entries[nentries].utime = cputime_to_clock_t(utime);
					proclist_info->entries[nentries].stime = cputime_to_clock_t(stime);
#else
					proclist_info->entries[nentries].utime = nsec_to_clock_t(utime);
					proclist_info->entries[nentries].stime = nsec_to_clock_t(stime);
#endif
				}

				nentries++;
#ifdef for_each_process_thread
		}
#else
				task_unlock(p);
#ifdef while_each_thread_all
			} while_each_thread_all(p, t);
		}
#else
			} while_each_thread(p, t);
		}
#endif
#endif

		rcu_read_unlock();

		proclist_info->n_entries = nentries;

		if (nentries >= pli.max_entries) {
			vpr_info("PPM_IOCTL_GET_PROCLIST: not enough space (%d avail, %d required)\n",
				(int)pli.max_entries,
				(int)nentries);

			if (copy_to_user((void *)arg, proclist_info, sizeof(struct ppm_proclist_info))) {
				ret = -EINVAL;
				goto cleanup_ioctl_procinfo;
			}

			ret = -ENOSPC;
			goto cleanup_ioctl_procinfo;
		} else {
			memsize = sizeof(struct ppm_proclist_info) + sizeof(struct ppm_proc_info) * nentries;

			if (copy_to_user((void *)arg, proclist_info, memsize)) {
				ret = -EINVAL;
				goto cleanup_ioctl_procinfo;
			}
		}

		ret = 0;
cleanup_ioctl_procinfo:
		vfree((void *)proclist_info);
		goto cleanup_ioctl_nolock;
	}

	if (cmd == PPM_IOCTL_GET_N_TRACEPOINT_HIT) {
		long __user *counters = (long __user *) arg;

		for_each_possible_cpu(cpu) {
			if (put_user(per_cpu(g_n_tracepoint_hit, cpu), &counters[cpu])) {
				ret = -EINVAL;
				goto cleanup_ioctl_nolock;
			}
		}
		ret = 0;
		goto cleanup_ioctl_nolock;
	} else if (cmd == PPM_IOCTL_GET_PROBE_VERSION) {
		if (copy_to_user((void *)arg, PROBE_VERSION, sizeof(PROBE_VERSION))) {
			ret = -EINVAL;
			goto cleanup_ioctl_nolock;
		}
		ret = 0;
		goto cleanup_ioctl_nolock;
	}

	mutex_lock(&g_consumer_mutex);

	consumer = ppm_find_consumer(consumer_id);
	if (!consumer) {
		pr_err("ioctl: unknown consumer %p\n", consumer_id);
		ret = -EBUSY;
		goto cleanup_ioctl;
	}

	switch (cmd) {
	case PPM_IOCTL_DISABLE_CAPTURE:
	{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		int ring_no = iminor(filp->f_path.dentry->d_inode);
#else
		int ring_no = iminor(filp->f_dentry->d_inode);
#endif
		struct ppm_ring_buffer_context *ring = per_cpu_ptr(consumer->ring_buffers, ring_no);

		if (!ring) {
			ASSERT(false);
			ret = -ENODEV;
			goto cleanup_ioctl;
		}

		ring->capture_enabled = false;

		vpr_info("PPM_IOCTL_DISABLE_CAPTURE for ring %d, consumer %p\n", ring_no, consumer_id);

		ret = 0;
		goto cleanup_ioctl;
	}
	case PPM_IOCTL_ENABLE_CAPTURE:
	{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		int ring_no = iminor(filp->f_path.dentry->d_inode);
#else
		int ring_no = iminor(filp->f_dentry->d_inode);
#endif
		struct ppm_ring_buffer_context *ring = per_cpu_ptr(consumer->ring_buffers, ring_no);

		if (!ring) {
			ASSERT(false);
			ret = -ENODEV;
			goto cleanup_ioctl;
		}

		ring->capture_enabled = true;

		vpr_info("PPM_IOCTL_ENABLE_CAPTURE for ring %d, consumer %p\n", ring_no, consumer_id);

		ret = 0;
		goto cleanup_ioctl;
	}
	case PPM_IOCTL_DISABLE_DROPPING_MODE:
	{
		struct event_data_t event_data;

		vpr_info("PPM_IOCTL_DISABLE_DROPPING_MODE, consumer %p\n", consumer_id);

		consumer->dropping_mode = 0;
		consumer->sampling_interval = 1000000000;
		consumer->sampling_ratio = 1;

		/*
		 * Push an event into the ring buffer so that the user can know that dropping
		 * mode has been disabled
		 */
		event_data.category = PPMC_CONTEXT_SWITCH;
		event_data.event_info.context_data.sched_prev = (void *)DEI_DISABLE_DROPPING;
		event_data.event_info.context_data.sched_next = (void *)0;

		record_event_consumer(consumer, PPME_SYSDIGEVENT_E, UF_NEVER_DROP, ppm_nsecs(), &event_data);

		ret = 0;
		goto cleanup_ioctl;
	}
	case PPM_IOCTL_ENABLE_DROPPING_MODE:
	{
		u32 new_sampling_ratio;

		consumer->dropping_mode = 1;
		vpr_info("PPM_IOCTL_ENABLE_DROPPING_MODE, consumer %p\n", consumer_id);

		new_sampling_ratio = (u32)arg;

		if (new_sampling_ratio != 1 &&
			new_sampling_ratio != 2 &&
			new_sampling_ratio != 4 &&
			new_sampling_ratio != 8 &&
			new_sampling_ratio != 16 &&
			new_sampling_ratio != 32 &&
			new_sampling_ratio != 64 &&
			new_sampling_ratio != 128) {
			pr_err("invalid sampling ratio %u\n", new_sampling_ratio);
			ret = -EINVAL;
			goto cleanup_ioctl;
		}

		consumer->sampling_interval = 1000000000 / new_sampling_ratio;
		consumer->sampling_ratio = new_sampling_ratio;

		vpr_info("new sampling ratio: %d\n", new_sampling_ratio);

		ret = 0;
		goto cleanup_ioctl;
	}
	case PPM_IOCTL_SET_SNAPLEN:
	{
		u32 new_snaplen;

		vpr_info("PPM_IOCTL_SET_SNAPLEN, consumer %p\n", consumer_id);
		new_snaplen = (u32)arg;

		if (new_snaplen > RW_MAX_SNAPLEN) {
			pr_err("invalid snaplen %u\n", new_snaplen);
			ret = -EINVAL;
			goto cleanup_ioctl;
		}

		consumer->snaplen = new_snaplen;

		vpr_info("new snaplen: %d\n", consumer->snaplen);

		ret = 0;
		goto cleanup_ioctl;
	}
	case PPM_IOCTL_SET_FULLCAPTURE_PORT_RANGE:
	{
		u32 encoded_port_range;

		vpr_info("PPM_IOCTL_SET_FULLCAPTURE_PORT_RANGE, consumer %p\n", consumer_id);
		encoded_port_range = (u32)arg;

		consumer->fullcapture_port_range_start = encoded_port_range & 0xFFFF;
		consumer->fullcapture_port_range_end = encoded_port_range >> 16;

		pr_info("new fullcapture_port_range_start: %d\n", (int)consumer->fullcapture_port_range_start);
		pr_info("new fullcapture_port_range_end: %d\n", (int)consumer->fullcapture_port_range_end);

		ret = 0;
		goto cleanup_ioctl;
	}
	case PPM_IOCTL_SET_STATSD_PORT:
	{
		consumer->statsd_port = (u16)arg;

		pr_info("new statsd_port: %d\n", (int)consumer->statsd_port);

		ret = 0;
		goto cleanup_ioctl;
	}
	case PPM_IOCTL_MASK_ZERO_EVENTS:
	{
		vpr_info("PPM_IOCTL_MASK_ZERO_EVENTS, consumer %p\n", consumer_id);

		bitmap_zero(g_events_mask, PPM_EVENT_MAX);

		/* Used for dropping events so they must stay on */
		set_bit(PPME_DROP_E, g_events_mask);
		set_bit(PPME_DROP_X, g_events_mask);

		ret = 0;
		goto cleanup_ioctl;
	}
	case PPM_IOCTL_MASK_SET_EVENT:
	{
		u32 syscall_to_set = (u32)arg;

		vpr_info("PPM_IOCTL_MASK_SET_EVENT (%u), consumer %p\n", syscall_to_set, consumer_id);

		if (syscall_to_set >= PPM_EVENT_MAX) {
			pr_err("invalid syscall %u\n", syscall_to_set);
			ret = -EINVAL;
			goto cleanup_ioctl;
		}

		set_bit(syscall_to_set, g_events_mask);

		ret = 0;
		goto cleanup_ioctl;
	}
	case PPM_IOCTL_MASK_UNSET_EVENT:
	{
		u32 syscall_to_unset = (u32)arg;

		vpr_info("PPM_IOCTL_MASK_UNSET_EVENT (%u), consumer %p\n", syscall_to_unset, consumer_id);

		if (syscall_to_unset >= PPM_EVENT_MAX) {
			pr_err("invalid syscall %u\n", syscall_to_unset);
			ret = -EINVAL;
			goto cleanup_ioctl;
		}

		clear_bit(syscall_to_unset, g_events_mask);

		ret = 0;
		goto cleanup_ioctl;
	}
	case PPM_IOCTL_DISABLE_DYNAMIC_SNAPLEN:
	{
		consumer->do_dynamic_snaplen = false;

		ret = 0;
		goto cleanup_ioctl;
	}
	case PPM_IOCTL_ENABLE_DYNAMIC_SNAPLEN:
	{
		consumer->do_dynamic_snaplen = true;

		ret = 0;
		goto cleanup_ioctl;
	}
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	case PPM_IOCTL_GET_VTID:
	case PPM_IOCTL_GET_VPID:
	{
		pid_t vid;
		struct pid *pid;
		struct task_struct *task;
		struct pid_namespace *ns;

		rcu_read_lock();
		pid = find_pid_ns(arg, &init_pid_ns);
		if (!pid) {
			rcu_read_unlock();
			ret = -EINVAL;
			goto cleanup_ioctl;
		}

		task = pid_task(pid, PIDTYPE_PID);
		if (!task) {
			rcu_read_unlock();
			ret = -EINVAL;
			goto cleanup_ioctl;
		}

		ns = ns_of_pid(pid);
		if (!pid) {
			rcu_read_unlock();
			ret = -EINVAL;
			goto cleanup_ioctl;
		}

		if (cmd == PPM_IOCTL_GET_VTID)
			vid = task_pid_nr_ns(task, ns);
		else
			vid = task_tgid_nr_ns(task, ns);

		rcu_read_unlock();
		ret = vid;
		goto cleanup_ioctl;
	}
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	case PPM_IOCTL_GET_CURRENT_TID:
		ret = task_pid_nr(current);
		goto cleanup_ioctl;
	case PPM_IOCTL_GET_CURRENT_PID:
		ret = task_tgid_nr(current);
		goto cleanup_ioctl;
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20) */
#ifdef CAPTURE_SIGNAL_DELIVERIES
	case PPM_IOCTL_DISABLE_SIGNAL_DELIVER:
	{
		vpr_info("PPM_IOCTL_DISABLE_SIGNAL_DELIVER\n");
		if (g_tracepoint_registered)
			compat_unregister_trace(signal_deliver_probe, "signal_deliver", tp_signal_deliver);
		ret = 0;
		goto cleanup_ioctl;
	}
	case PPM_IOCTL_ENABLE_SIGNAL_DELIVER:
	{
		vpr_info("PPM_IOCTL_ENABLE_SIGNAL_DELIVER\n");
		if (g_tracepoint_registered)
			compat_register_trace(signal_deliver_probe, "signal_deliver", tp_signal_deliver);
		ret = 0;
		goto cleanup_ioctl;
	}
#endif
	case PPM_IOCTL_SET_TRACERS_CAPTURE:
	{
		vpr_info("PPM_IOCTL_SET_TRACERS_CAPTURE, consumer %p\n", consumer_id);
		g_tracers_enabled = true;
		ret = 0;
		goto cleanup_ioctl;
	}
	case PPM_IOCTL_SET_SIMPLE_MODE:
	{
		vpr_info("PPM_IOCTL_SET_SIMPLE_MODE, consumer %p\n", consumer_id);
		g_simple_mode_enabled = true;
		ret = 0;
		goto cleanup_ioctl;
	}
	case PPM_IOCTL_ENABLE_PAGE_FAULTS:
	{
		vpr_info("PPM_IOCTL_ENABLE_PAGE_FAULTS\n");
#ifdef CAPTURE_PAGE_FAULTS
		ASSERT(g_tracepoint_registered);

		if (g_fault_tracepoint_disabled) {
			pr_err("kernel page fault tracepoints are disabled\n");
			ret = -EPERM;
			goto cleanup_ioctl;
		}

		if (!g_fault_tracepoint_registered) {
			ret = compat_register_trace(page_fault_probe, "page_fault_user", tp_page_fault_user);
			if (ret) {
				pr_err("can't create the page_fault_user tracepoint\n");
				ret = -EINVAL;
				goto cleanup_ioctl;
			}

			ret = compat_register_trace(page_fault_probe, "page_fault_kernel", tp_page_fault_kernel);
			if (ret) {
				pr_err("can't create the page_fault_kernel tracepoint\n");
				ret = -EINVAL;
				goto err_page_fault_kernel;
			}

			g_fault_tracepoint_registered = true;
		}

		ret = 0;
		goto cleanup_ioctl;
#else
		pr_err("kernel doesn't support page fault tracepoints\n");
		ret = -EINVAL;
		goto cleanup_ioctl;
#endif
	}
	default:
		ret = -ENOTTY;
		goto cleanup_ioctl;
	}

#ifdef CAPTURE_PAGE_FAULTS
err_page_fault_kernel:
	compat_unregister_trace(page_fault_probe, "page_fault_user", tp_page_fault_user);
#endif
cleanup_ioctl:
	mutex_unlock(&g_consumer_mutex);
cleanup_ioctl_nolock:
	return ret;
}

static int ppm_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret;
	struct task_struct *consumer_id = filp->private_data;
	struct ppm_consumer_t *consumer = NULL;

	mutex_lock(&g_consumer_mutex);

	consumer = ppm_find_consumer(consumer_id);
	if (!consumer) {
		pr_err("mmap: unknown consumer %p\n", consumer_id);
		ret = -EIO;
		goto cleanup_mmap;
	}

	if (vma->vm_pgoff == 0) {
		long length = vma->vm_end - vma->vm_start;
		unsigned long useraddr = vma->vm_start;
		unsigned long pfn;
		char *vmalloc_area_ptr;
		char *orig_vmalloc_area_ptr;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		int ring_no = iminor(filp->f_path.dentry->d_inode);
#else
		int ring_no = iminor(filp->f_dentry->d_inode);
#endif
		struct ppm_ring_buffer_context *ring;

		vpr_info("mmap for consumer %p, CPU %d, start=%lu len=%ld page_size=%lu\n",
			   consumer_id,
		       ring_no,
		       useraddr,
		       length,
		       PAGE_SIZE);

		/*
		 * Enforce ring buffer size
		 */
		if (RING_BUF_SIZE < 2 * PAGE_SIZE) {
			pr_err("Ring buffer size too small (%ld bytes, must be at least %ld bytes\n",
			       (long)RING_BUF_SIZE,
			       (long)PAGE_SIZE);
			ret = -EIO;
			goto cleanup_mmap;
		}

		if (RING_BUF_SIZE / PAGE_SIZE * PAGE_SIZE != RING_BUF_SIZE) {
			pr_err("Ring buffer size is not a multiple of the page size\n");
			ret = -EIO;
			goto cleanup_mmap;
		}

		/*
		 * Retrieve the ring structure for this CPU
		 */
		ring = per_cpu_ptr(consumer->ring_buffers, ring_no);
		if (!ring) {
			ASSERT(false);
			ret = -ENODEV;
			goto cleanup_mmap;
		}

		if (length <= PAGE_SIZE) {
			/*
			 * When the size requested by the user is smaller than a page, we assume
			 * she's mapping the ring info structure
			 */
			vpr_info("mapping the ring info\n");

			vmalloc_area_ptr = (char *)ring->info;
			orig_vmalloc_area_ptr = vmalloc_area_ptr;

			pfn = vmalloc_to_pfn(vmalloc_area_ptr);

			ret = remap_pfn_range(vma, useraddr, pfn,
					      PAGE_SIZE, pgprot_encrypted(PAGE_SHARED));
			if (ret < 0) {
				pr_err("remap_pfn_range failed (1)\n");
				goto cleanup_mmap;
			}

			ret = 0;
			goto cleanup_mmap;
		} else if (length == RING_BUF_SIZE * 2) {
			long mlength;

			/*
			 * When the size requested by the user equals the ring buffer size, we map the full
			 * buffer
			 */
			vpr_info("mapping the data buffer\n");

			vmalloc_area_ptr = (char *)ring->buffer;
			orig_vmalloc_area_ptr = vmalloc_area_ptr;

			/*
			 * Validate that the buffer access is read only
			 */
			if (vma->vm_flags & VM_WRITE) {
				pr_err("invalid mmap flags 0x%lx\n", vma->vm_flags);
				ret = -EIO;
				goto cleanup_mmap;
			}

			/*
			 * Map each single page of the buffer
			 */
			mlength = length / 2;

			while (mlength > 0) {
				pfn = vmalloc_to_pfn(vmalloc_area_ptr);

				ret = remap_pfn_range(vma, useraddr, pfn,
						      PAGE_SIZE, pgprot_encrypted(PAGE_SHARED));
				if (ret < 0) {
					pr_err("remap_pfn_range failed (1)\n");
					goto cleanup_mmap;
				}

				useraddr += PAGE_SIZE;
				vmalloc_area_ptr += PAGE_SIZE;
				mlength -= PAGE_SIZE;
			}

			/*
			 * Remap a second copy of the buffer pages at the end of the buffer.
			 * This effectively mirrors the buffer at its end and helps simplify buffer management in userland.
			 */
			vmalloc_area_ptr = orig_vmalloc_area_ptr;
			mlength = length / 2;

			while (mlength > 0) {
				pfn = vmalloc_to_pfn(vmalloc_area_ptr);

				ret = remap_pfn_range(vma, useraddr, pfn,
						      PAGE_SIZE, pgprot_encrypted(PAGE_SHARED));
				if (ret < 0) {
					pr_err("remap_pfn_range failed (1)\n");
					goto cleanup_mmap;
				}

				useraddr += PAGE_SIZE;
				vmalloc_area_ptr += PAGE_SIZE;
				mlength -= PAGE_SIZE;
			}

			ret = 0;
			goto cleanup_mmap;
		}

		pr_err("Invalid mmap size %ld\n", length);
		ret = -EIO;
		goto cleanup_mmap;
	}

	pr_err("invalid pgoff %lu, must be 0\n", vma->vm_pgoff);
	ret = -EIO;

cleanup_mmap:
	mutex_unlock(&g_consumer_mutex);

	return ret;
}

/* Argument list sizes for sys_socketcall */
#define AL(x) ((x) * sizeof(unsigned long))
static const unsigned char nas[21] = {
	AL(0), AL(3), AL(3), AL(3), AL(2), AL(3),
	AL(3), AL(3), AL(4), AL(4), AL(4), AL(6),
	AL(6), AL(2), AL(5), AL(5), AL(3), AL(3),
	AL(4), AL(5), AL(4)
};
#undef AL
#ifdef CONFIG_COMPAT
#define AL(x) ((x) * sizeof(compat_ulong_t))
static const unsigned char compat_nas[21] = {
	AL(0), AL(3), AL(3), AL(3), AL(2), AL(3),
	AL(3), AL(3), AL(4), AL(4), AL(4), AL(6),
	AL(6), AL(2), AL(5), AL(5), AL(3), AL(3),
	AL(4), AL(5), AL(4)
};
#undef AL
#endif


#ifdef _HAS_SOCKETCALL
static enum ppm_event_type parse_socketcall(struct event_filler_arguments *filler_args, struct pt_regs *regs)
{
	unsigned long __user args[6] = {};
	unsigned long __user *scargs;
	int socketcall_id;
	ppm_syscall_get_arguments(current, regs, args);
	socketcall_id = args[0];
	scargs = (unsigned long __user *)args[1];

	if (unlikely(socketcall_id < SYS_SOCKET ||
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
		socketcall_id > SYS_SENDMMSG))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
		socketcall_id > SYS_RECVMMSG))
#else
		socketcall_id > SYS_ACCEPT4))
#endif
		return PPME_GENERIC_E;

#ifdef CONFIG_COMPAT
	if (unlikely(filler_args->compat)) {
		compat_ulong_t socketcall_args32[6];
		int j;

		if (unlikely(ppm_copy_from_user(socketcall_args32, compat_ptr(args[1]), compat_nas[socketcall_id])))
			return PPME_GENERIC_E;
		for (j = 0; j < 6; ++j)
			filler_args->socketcall_args[j] = (unsigned long)socketcall_args32[j];
	} else {
#endif
		if (unlikely(ppm_copy_from_user(filler_args->socketcall_args, scargs, nas[socketcall_id])))
			return PPME_GENERIC_E;
#ifdef CONFIG_COMPAT
	}
#endif

	switch (socketcall_id) {
	case SYS_SOCKET:
		return PPME_SOCKET_SOCKET_E;
	case SYS_BIND:
		return PPME_SOCKET_BIND_E;
	case SYS_CONNECT:
		return PPME_SOCKET_CONNECT_E;
	case SYS_LISTEN:
		return PPME_SOCKET_LISTEN_E;
	case SYS_ACCEPT:
		return PPME_SOCKET_ACCEPT_5_E;
	case SYS_GETSOCKNAME:
		return PPME_SOCKET_GETSOCKNAME_E;
	case SYS_GETPEERNAME:
		return PPME_SOCKET_GETPEERNAME_E;
	case SYS_SOCKETPAIR:
		return PPME_SOCKET_SOCKETPAIR_E;
	case SYS_SEND:
		return PPME_SOCKET_SEND_E;
	case SYS_SENDTO:
		return PPME_SOCKET_SENDTO_E;
	case SYS_RECV:
		return PPME_SOCKET_RECV_E;
	case SYS_RECVFROM:
		return PPME_SOCKET_RECVFROM_E;
	case SYS_SHUTDOWN:
		return PPME_SOCKET_SHUTDOWN_E;
	case SYS_SETSOCKOPT:
		return PPME_SOCKET_SETSOCKOPT_E;
	case SYS_GETSOCKOPT:
		return PPME_SOCKET_GETSOCKOPT_E;
	case SYS_SENDMSG:
		return PPME_SOCKET_SENDMSG_E;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	case SYS_SENDMMSG:
		return PPME_SOCKET_SENDMMSG_E;
#endif
	case SYS_RECVMSG:
		return PPME_SOCKET_RECVMSG_E;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	case SYS_RECVMMSG:
		return PPME_SOCKET_RECVMMSG_E;
#endif
	case SYS_ACCEPT4:
		return PPME_SOCKET_ACCEPT4_5_E;
	default:
		ASSERT(false);
		return PPME_GENERIC_E;
	}
}
#endif /* _HAS_SOCKETCALL */

static inline void record_drop_e(struct ppm_consumer_t *consumer,
                                 nanoseconds ns,
                                 enum syscall_flags drop_flags)
{
	struct event_data_t event_data = {0};

	if (record_event_consumer(consumer, PPME_DROP_E, UF_NEVER_DROP, ns, &event_data) == 0) {
		consumer->need_to_insert_drop_e = 1;
	} else {
		if (consumer->need_to_insert_drop_e == 1 && !(drop_flags & UF_ATOMIC)) {
			pr_err("drop enter event delayed insert\n");
		}

		consumer->need_to_insert_drop_e = 0;
	}
}

static inline void record_drop_x(struct ppm_consumer_t *consumer,
                                 nanoseconds ns,
                                 enum syscall_flags drop_flags)
{
	struct event_data_t event_data = {0};

	if (record_event_consumer(consumer, PPME_DROP_X, UF_NEVER_DROP, ns, &event_data) == 0) {
		consumer->need_to_insert_drop_x = 1;
	} else {
		if (consumer->need_to_insert_drop_x == 1 && !(drop_flags & UF_ATOMIC)) {
			pr_err("drop exit event delayed insert\n");
		}

		consumer->need_to_insert_drop_x = 0;
	}
}

// Return 1 if the event should be dropped, else 0
static inline int drop_nostate_event(enum ppm_event_type event_type,
				     struct pt_regs *regs)
{
	unsigned long args[6] = {};
	unsigned long arg = 0;
	int close_fd = -1;
	struct files_struct *files;
	struct fdtable *fdt;
	bool drop = false;

	switch (event_type) {
	case PPME_SYSCALL_CLOSE_X:
	case PPME_SOCKET_BIND_X:
		if (syscall_get_return_value(current, regs) < 0)
			drop = true;
		break;
	case PPME_SYSCALL_CLOSE_E:
		/*
		 * It's annoying but valid for a program to make a large number of
		 * close() calls on nonexistent fds. That can cause driver cpu usage
		 * to spike dramatically, so drop close events if the fd is not valid.
		 *
		 * The invalid fd events don't matter to userspace in dropping mode,
		 * so we do this before the UF_NEVER_DROP check
		 */
		ppm_syscall_get_arguments(current, regs, args);
		arg = args[0];
		close_fd = (int)arg;

		files = current->files;
		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);
		if (close_fd < 0 || close_fd >= fdt->max_fds ||
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0))
		    !FD_ISSET(close_fd, fdt->open_fds)
#else
		    !fd_is_open(close_fd, fdt)
#endif
			) {
			drop = true;
		}
		spin_unlock(&files->file_lock);
		break;
	case PPME_SYSCALL_FCNTL_E:
	case PPME_SYSCALL_FCNTL_X:
		// cmd arg
		ppm_syscall_get_arguments(current, regs, args);
		arg = args[1];
		if (arg != F_DUPFD && arg != F_DUPFD_CLOEXEC)
			drop = true;
		break;
	default:
		break;
	}

	if (drop)
		return 1;
	else
		return 0;
}

// Return 1 if the event should be dropped, else 0
static inline int drop_event(struct ppm_consumer_t *consumer,
			     enum ppm_event_type event_type,
			     enum syscall_flags drop_flags,
			     nanoseconds ns,
			     struct pt_regs *regs)
{
	int maybe_ret = 0;

	if (consumer->dropping_mode) {
		maybe_ret = drop_nostate_event(event_type, regs);
		if (maybe_ret > 0)
			return maybe_ret;
	}

	if (drop_flags & UF_NEVER_DROP) {
		ASSERT((drop_flags & UF_ALWAYS_DROP) == 0);
		return 0;
	}

	if (consumer->dropping_mode) {
		if (drop_flags & UF_ALWAYS_DROP) {
			ASSERT((drop_flags & UF_NEVER_DROP) == 0);
			return 1;
		}

		if (consumer->sampling_interval < SECOND_IN_NS &&
		    (ns % SECOND_IN_NS) >= consumer->sampling_interval) {
			if (consumer->is_dropping == 0) {
				consumer->is_dropping = 1;
				record_drop_e(consumer, ns, drop_flags);
			}

			return 1;
		}

		if (consumer->is_dropping == 1) {
			consumer->is_dropping = 0;
			record_drop_x(consumer, ns, drop_flags);
		}
	}

	return 0;
}

static void record_event_all_consumers(enum ppm_event_type event_type,
	enum syscall_flags drop_flags,
	struct event_data_t *event_datap)
{
	struct ppm_consumer_t *consumer;
	nanoseconds ns = ppm_nsecs();

	rcu_read_lock();
	list_for_each_entry_rcu(consumer, &g_consumer_list, node) {
		record_event_consumer(consumer, event_type, drop_flags, ns, event_datap);
	}
	rcu_read_unlock();
}

/*
 * Returns 0 if the event is dropped
 */
static int record_event_consumer(struct ppm_consumer_t *consumer,
	enum ppm_event_type event_type,
	enum syscall_flags drop_flags,
	nanoseconds ns,
	struct event_data_t *event_datap)
{
	int res = 0;
	size_t event_size = 0;
	int next;
	u32 freespace;
	u32 usedspace;
	u32 delta_from_end;
	struct event_filler_arguments args;
	u32 ttail;
	u32 head;
	struct ppm_ring_buffer_context *ring;
	struct ppm_ring_buffer_info *ring_info;
	int drop = 1;
	int32_t cbres = PPM_SUCCESS;
	int cpu;

	if (!test_bit(event_type, g_events_mask))
		return res;

	if (event_type != PPME_DROP_E && event_type != PPME_DROP_X) {
		if (consumer->need_to_insert_drop_e == 1)
			record_drop_e(consumer, ns, drop_flags);
		else if (consumer->need_to_insert_drop_x == 1)
			record_drop_x(consumer, ns, drop_flags);

		if (drop_event(consumer,
		               event_type,
		               drop_flags,
		               ns,
		               event_datap->event_info.syscall_data.regs))
			return res;
	}

	/*
	 * FROM THIS MOMENT ON, WE HAVE TO BE SUPER FAST
	 */
	cpu = get_cpu();
	ring = per_cpu_ptr(consumer->ring_buffers, cpu);
	ASSERT(ring);

	ring_info = ring->info;

	if (!ring->capture_enabled) {
		put_cpu();
		return res;
	}

	ring_info->n_evts++;
	if (event_datap->category == PPMC_CONTEXT_SWITCH && event_datap->event_info.context_data.sched_prev != NULL) {
		if (event_type != PPME_SYSDIGEVENT_E && event_type != PPME_CPU_HOTPLUG_E) {
			ASSERT(event_datap->event_info.context_data.sched_prev != NULL);
			ASSERT(event_datap->event_info.context_data.sched_next != NULL);
			ring_info->n_context_switches++;
		}
	}

	/*
	 * Preemption gate
	 */
	if (unlikely(atomic_inc_return(&ring->preempt_count) != 1)) {
		/* When this driver executing a filler calls ppm_copy_from_user(),
		 * even if the page fault is disabled, the page fault tracepoint gets
		 * called very early in the page fault handler, way before the kernel
		 * terminates it, so this is legit. Still not sure how to solve this,
		 * so for the moment handle this case by not complaining and ignoring
		 * the false alarm if the preemption exception is generated by
		 * page_fault_kernel. The alternative would be to disable the kernel
		 * tracepoint completely, but there is value in seeing page faults
		 * generated on this side, so let's see if someone complains.
		 * This means that effectively those events would be lost.
		 */
		if (event_type != PPME_PAGE_FAULT_E) {
			ring_info->n_preemptions++;
			ASSERT(false);
		}
		atomic_dec(&ring->preempt_count);
		put_cpu();
		return res;
	}

	/*
	 * Calculate the space currently available in the buffer
	 */
	head = ring_info->head;
	ttail = ring_info->tail;

	if (ttail > head)
		freespace = ttail - head - 1;
	else
		freespace = RING_BUF_SIZE + ttail - head - 1;

	usedspace = RING_BUF_SIZE - freespace - 1;
	delta_from_end = RING_BUF_SIZE + (2 * PAGE_SIZE) - head - 1;

	ASSERT(freespace <= RING_BUF_SIZE);
	ASSERT(usedspace <= RING_BUF_SIZE);
	ASSERT(ttail <= RING_BUF_SIZE);
	ASSERT(head <= RING_BUF_SIZE);
	ASSERT(delta_from_end < RING_BUF_SIZE + (2 * PAGE_SIZE));
	ASSERT(delta_from_end > (2 * PAGE_SIZE) - 1);
#ifdef _HAS_SOCKETCALL
	/*
	 * If this is a socketcall system call, determine the correct event type
	 * by parsing the arguments and patch event_type accordingly
	 * A bit of explanation: most linux architectures don't have a separate
	 * syscall for each of the socket functions (bind, connect...). Instead,
	 * the socket functions are aggregated into a single syscall, called
	 * socketcall. The first socketcall argument is the call type, while the
	 * second argument contains a pointer to the arguments of the original
	 * call. I guess this was done to reduce the number of syscalls...
	 */
	if (event_datap->category == PPMC_SYSCALL && event_datap->event_info.syscall_data.regs && event_datap->event_info.syscall_data.id == event_datap->socketcall_syscall) {
		enum ppm_event_type tet;

		args.is_socketcall = true;
		args.compat = event_datap->compat;
		tet = parse_socketcall(&args, event_datap->event_info.syscall_data.regs);

		if (event_type == PPME_GENERIC_E)
			event_type = tet;
		else
			event_type = tet + 1;

	} else {
		args.is_socketcall = false;
		args.compat = false;
	}

	args.socketcall_syscall = event_datap->socketcall_syscall;
#endif

	ASSERT(event_type < PPM_EVENT_MAX);

	/*
	 * Determine how many arguments this event has
	 */
	args.nargs = g_event_info[event_type].nparams;
	args.arg_data_offset = args.nargs * sizeof(u16);

	/*
	 * Make sure we have enough space for the event header.
	 * We need at least space for the header plus 16 bit per parameter for the lengths.
	 */
	if (likely(freespace >= sizeof(struct ppm_evt_hdr) + args.arg_data_offset)) {
		/*
		 * Populate the header
		 */
		struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)(ring->buffer + head);

#ifdef PPM_ENABLE_SENTINEL
		hdr->sentinel_begin = ring->nevents;
#endif
		hdr->ts = ns;
		hdr->tid = current->pid;
		hdr->type = event_type;
		hdr->nparams = args.nargs;

		/*
		 * Populate the parameters for the filler callback
		 */
		args.consumer = consumer;
		args.buffer = ring->buffer + head + sizeof(struct ppm_evt_hdr);
#ifdef PPM_ENABLE_SENTINEL
		args.sentinel = ring->nevents;
#endif
		args.buffer_size = min(freespace, delta_from_end) - sizeof(struct ppm_evt_hdr); /* freespace is guaranteed to be bigger than sizeof(struct ppm_evt_hdr) */
		args.event_type = event_type;

		if (event_datap->category == PPMC_SYSCALL) {
			args.regs = event_datap->event_info.syscall_data.regs;
			args.syscall_id = event_datap->event_info.syscall_data.id;
			args.cur_g_syscall_code_routing_table = event_datap->event_info.syscall_data.cur_g_syscall_code_routing_table;
			args.compat = event_datap->compat;
		} else {
			args.regs = NULL;
			args.syscall_id = -1;
			args.cur_g_syscall_code_routing_table = NULL;
			args.compat = false;
		}

		if (event_datap->category == PPMC_CONTEXT_SWITCH) {
			args.sched_prev = event_datap->event_info.context_data.sched_prev;
			args.sched_next = event_datap->event_info.context_data.sched_next;
		} else {
			args.sched_prev = NULL;
			args.sched_next = NULL;
		}

		if (event_datap->category == PPMC_SIGNAL) {
			args.signo = event_datap->event_info.signal_data.sig;
			if (event_datap->event_info.signal_data.info == NULL) {
				args.spid = (__kernel_pid_t) 0;
			} else if (args.signo == SIGKILL) {
				args.spid = event_datap->event_info.signal_data.info->_sifields._kill._pid;
			} else if (args.signo == SIGTERM || args.signo == SIGHUP || args.signo == SIGINT ||
					args.signo == SIGTSTP || args.signo == SIGQUIT) {
				if (event_datap->event_info.signal_data.info->si_code == SI_USER ||
						event_datap->event_info.signal_data.info->si_code == SI_QUEUE ||
						event_datap->event_info.signal_data.info->si_code <= 0) {
					args.spid = event_datap->event_info.signal_data.info->si_pid;
				}
			} else if (args.signo == SIGCHLD) {
				args.spid = event_datap->event_info.signal_data.info->_sifields._sigchld._pid;
			} else if (args.signo >= SIGRTMIN && args.signo <= SIGRTMAX) {
				args.spid = event_datap->event_info.signal_data.info->_sifields._rt._pid;
			} else {
				args.spid = (__kernel_pid_t) 0;
			}
		} else {
			args.signo = 0;
			args.spid = (__kernel_pid_t) 0;
		}
		args.dpid = current->pid;

		if (event_datap->category == PPMC_PAGE_FAULT)
			args.fault_data = event_datap->event_info.fault_data;

		args.curarg = 0;
		args.arg_data_size = args.buffer_size - args.arg_data_offset;
		args.nevents = ring->nevents;
		args.str_storage = ring->str_storage;
		args.enforce_snaplen = false;

		/*
		 * Fire the filler callback
		 */
		if (likely(g_ppm_events[event_type].filler_callback)) {
			cbres = g_ppm_events[event_type].filler_callback(&args);
		} else {
			pr_err("corrupted filler for event type %d: NULL callback\n", event_type);
			ASSERT(0);
		}

		if (likely(cbres == PPM_SUCCESS)) {
			/*
			 * Validate that the filler added the right number of parameters
			 */
			if (likely(args.curarg == args.nargs)) {
				/*
				 * The event was successfully inserted in the buffer
				 */
				event_size = sizeof(struct ppm_evt_hdr) + args.arg_data_offset;
				hdr->len = event_size;
				drop = 0;
			} else {
				pr_err("corrupted filler for event type %d (added %u args, should have added %u)\n",
				       event_type,
				       args.curarg,
				       args.nargs);
				ASSERT(0);
			}
		}
	}

	if (likely(!drop)) {
		res = 1;

		next = head + event_size;

		if (unlikely(next >= RING_BUF_SIZE)) {
			/*
			 * If something has been written in the cushion space at the end of
			 * the buffer, copy it to the beginning and wrap the head around.
			 * Note, we don't check that the copy fits because we assume that
			 * filler_callback failed if the space was not enough.
			 */
			if (next > RING_BUF_SIZE) {
				memcpy(ring->buffer,
				ring->buffer + RING_BUF_SIZE,
				next - RING_BUF_SIZE);
			}

			next -= RING_BUF_SIZE;
		}

		/*
		 * Make sure all the memory has been written in real memory before
		 * we update the head and the user space process (on another CPU)
		 * can access the buffer.
		 */
		smp_wmb();

		ring_info->head = next;

		++ring->nevents;
	} else {
		if (cbres == PPM_SUCCESS) {
			ASSERT(freespace < sizeof(struct ppm_evt_hdr) + args.arg_data_offset);
			ring_info->n_drops_buffer++;
		} else if (cbres == PPM_FAILURE_INVALID_USER_MEMORY) {
#ifdef _DEBUG
			pr_err("Invalid read from user for event %d\n", event_type);
#endif
			ring_info->n_drops_pf++;
		} else if (cbres == PPM_FAILURE_BUFFER_FULL) {
			ring_info->n_drops_buffer++;
		} else {
			ASSERT(false);
		}
	}

	if (MORE_THAN_ONE_SECOND_AHEAD(ns, ring->last_print_time + 1) && !(drop_flags & UF_ATOMIC)) {
		vpr_info("consumer:%p CPU:%d, use:%d%%, ev:%llu, dr_buf:%llu, dr_pf:%llu, pr:%llu, cs:%llu\n",
			   consumer->consumer_id,
		       smp_processor_id(),
		       (usedspace * 100) / RING_BUF_SIZE,
		       ring_info->n_evts,
		       ring_info->n_drops_buffer,
		       ring_info->n_drops_pf,
		       ring_info->n_preemptions,
		       ring->info->n_context_switches);

		ring->last_print_time = ns;
	}

	atomic_dec(&ring->preempt_count);
	put_cpu();

	return res;
}

static inline void g_n_tracepoint_hit_inc(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	this_cpu_inc(g_n_tracepoint_hit);
#elif defined(this_cpu_inc)
	/* this_cpu_inc has been added with 2.6.33 but backported by RHEL/CentOS to 2.6.32
	 * so just checking the existence of the symbol rather than matching the kernel version
	 * https://github.com/torvalds/linux/commit/7340a0b15280c9d902c7dd0608b8e751b5a7c403
	 *
	 * per_cpu_var removed with:
	 * https://github.com/torvalds/linux/commit/dd17c8f72993f9461e9c19250e3f155d6d99df22
	 */
	this_cpu_inc(per_cpu_var(g_n_tracepoint_hit));
#endif
}

TRACEPOINT_PROBE(syscall_enter_probe, struct pt_regs *regs, long id)
{
	long table_index;
	const struct syscall_evt_pair *cur_g_syscall_table = g_syscall_table;
	const enum ppm_syscall_code *cur_g_syscall_code_routing_table = g_syscall_code_routing_table;
	bool compat = false;
#ifdef __NR_socketcall
	int socketcall_syscall = __NR_socketcall;
#else
	int socketcall_syscall = -1;
#endif

#if defined(CONFIG_X86_64) && defined(CONFIG_IA32_EMULATION)
	/*
	 * If this is a 32bit process running on a 64bit kernel (see the CONFIG_IA32_EMULATION
	 * kernel flag), we switch to the ia32 syscall table.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	if (in_ia32_syscall()) {
#else
	if (unlikely(task_thread_info(current)->status & TS_COMPAT)) {
#endif
		cur_g_syscall_table = g_syscall_ia32_table;
		cur_g_syscall_code_routing_table = g_syscall_ia32_code_routing_table;
		socketcall_syscall = __NR_ia32_socketcall;
		compat = true;
	}
#endif

	g_n_tracepoint_hit_inc();

	table_index = id - SYSCALL_TABLE_ID0;
	if (likely(table_index >= 0 && table_index < SYSCALL_TABLE_SIZE)) {
		struct event_data_t event_data;
		int used = cur_g_syscall_table[table_index].flags & UF_USED;
		enum syscall_flags drop_flags = cur_g_syscall_table[table_index].flags;
		enum ppm_event_type type;

		/*
		 * Simple mode event filtering
		 */
		if (g_simple_mode_enabled) {
			if ((drop_flags & UF_SIMPLEDRIVER_KEEP) == 0) {
				return;
			}
		}

#ifdef _HAS_SOCKETCALL
		if (id == socketcall_syscall) {
			used = true;
			drop_flags = UF_NEVER_DROP;
			type = PPME_GENERIC_E;
		} else
			type = cur_g_syscall_table[table_index].enter_event_type;
#else
		type = cur_g_syscall_table[table_index].enter_event_type;
#endif

		event_data.category = PPMC_SYSCALL;
		event_data.event_info.syscall_data.regs = regs;
		event_data.event_info.syscall_data.id = id;
		event_data.event_info.syscall_data.cur_g_syscall_code_routing_table = cur_g_syscall_code_routing_table;
		event_data.socketcall_syscall = socketcall_syscall;
		event_data.compat = compat;

		if (used)
			record_event_all_consumers(type, drop_flags, &event_data);
		else
			record_event_all_consumers(PPME_GENERIC_E, UF_ALWAYS_DROP, &event_data);
	}
}

TRACEPOINT_PROBE(syscall_exit_probe, struct pt_regs *regs, long ret)
{
	int id;
	long table_index;
	const struct syscall_evt_pair *cur_g_syscall_table = g_syscall_table;
	const enum ppm_syscall_code *cur_g_syscall_code_routing_table = g_syscall_code_routing_table;
	bool compat = false;
#ifdef __NR_socketcall
	int socketcall_syscall = __NR_socketcall;
#else
	int socketcall_syscall = -1;
#endif

	id = syscall_get_nr(current, regs);

#if defined(CONFIG_X86_64) && defined(CONFIG_IA32_EMULATION)
	/*
	 * When a process does execve from 64bit to 32bit, TS_COMPAT is marked true
	 * but the id of the syscall is __NR_execve, so to correctly parse it we need to
	 * use 64bit syscall table. On 32bit __NR_execve is equal to __NR_ia32_oldolduname
	 * which is a very old syscall, not used anymore by most applications
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	if (in_ia32_syscall() && id != __NR_execve) {
#else
	if (unlikely((task_thread_info(current)->status & TS_COMPAT) && id != __NR_execve)) {
#endif
		cur_g_syscall_table = g_syscall_ia32_table;
		cur_g_syscall_code_routing_table = g_syscall_ia32_code_routing_table;
		socketcall_syscall = __NR_ia32_socketcall;
		compat = true;
	}
#endif

	g_n_tracepoint_hit_inc();

	table_index = id - SYSCALL_TABLE_ID0;
	if (likely(table_index >= 0 && table_index < SYSCALL_TABLE_SIZE)) {
		struct event_data_t event_data;
		int used = cur_g_syscall_table[table_index].flags & UF_USED;
		enum syscall_flags drop_flags = cur_g_syscall_table[table_index].flags;
		enum ppm_event_type type;

		/*
		 * Simple mode event filtering
		 */
		if (g_simple_mode_enabled) {
			if ((drop_flags & UF_SIMPLEDRIVER_KEEP) == 0) {
				return;
			}
		}

#ifdef _HAS_SOCKETCALL
		if (id == socketcall_syscall) {
			used = true;
			drop_flags = UF_NEVER_DROP;
			type = PPME_GENERIC_X;
		} else
			type = cur_g_syscall_table[table_index].exit_event_type;
#else
		type = cur_g_syscall_table[table_index].exit_event_type;
#endif

		event_data.category = PPMC_SYSCALL;
		event_data.event_info.syscall_data.regs = regs;
		event_data.event_info.syscall_data.id = id;
		event_data.event_info.syscall_data.cur_g_syscall_code_routing_table = cur_g_syscall_code_routing_table;
		event_data.socketcall_syscall = socketcall_syscall;
		event_data.compat = compat;

		if (used)
			record_event_all_consumers(type, drop_flags, &event_data);
		else
			record_event_all_consumers(PPME_GENERIC_X, UF_ALWAYS_DROP, &event_data);
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 1)
int __access_remote_vm(struct task_struct *t, struct mm_struct *mm, unsigned long addr,
		       void *buf, int len, int write);
#endif

TRACEPOINT_PROBE(syscall_procexit_probe, struct task_struct *p)
{
	struct event_data_t event_data;

	g_n_tracepoint_hit_inc();

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	if (unlikely(current->flags & PF_KTHREAD)) {
#else
	if (unlikely(current->flags & PF_BORROWED_MM)) {
#endif
		/*
		 * We are not interested in kernel threads
		 */
		return;
	}

	event_data.category = PPMC_CONTEXT_SWITCH;
	event_data.event_info.context_data.sched_prev = p;
	event_data.event_info.context_data.sched_next = p;

	record_event_all_consumers(PPME_PROCEXIT_1_E, UF_NEVER_DROP, &event_data);
}

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#ifdef CAPTURE_CONTEXT_SWITCHES
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
TRACEPOINT_PROBE(sched_switch_probe, struct rq *rq, struct task_struct *prev, struct task_struct *next)
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
TRACEPOINT_PROBE(sched_switch_probe, struct task_struct *prev, struct task_struct *next)
#else
TRACEPOINT_PROBE(sched_switch_probe, bool preempt, struct task_struct *prev, struct task_struct *next)
#endif
{
	struct event_data_t event_data;

	g_n_tracepoint_hit_inc();

	event_data.category = PPMC_CONTEXT_SWITCH;
	event_data.event_info.context_data.sched_prev = prev;
	event_data.event_info.context_data.sched_next = next;

	/*
	 * Need to indicate ATOMIC (i.e. interrupt) context to avoid the event
	 * handler calling printk() and potentially deadlocking the system.
	 */
	record_event_all_consumers(PPME_SCHEDSWITCH_6_E, UF_USED | UF_ATOMIC, &event_data);
}
#endif

#ifdef CAPTURE_SIGNAL_DELIVERIES

static __always_inline int siginfo_not_a_pointer(struct siginfo* info)
{
#ifdef SEND_SIG_FORCED
	return info == SEND_SIG_NOINFO || info == SEND_SIG_PRIV || SEND_SIG_FORCED;
#else
	return info == (struct siginfo*)SEND_SIG_NOINFO || info == (struct siginfo*)SEND_SIG_PRIV;
#endif
}

TRACEPOINT_PROBE(signal_deliver_probe, int sig, struct siginfo *info, struct k_sigaction *ka)
{
	struct event_data_t event_data;

	g_n_tracepoint_hit_inc();

	event_data.category = PPMC_SIGNAL;
	event_data.event_info.signal_data.sig = sig;
	if (siginfo_not_a_pointer(info))
		event_data.event_info.signal_data.info = NULL;
	else
		event_data.event_info.signal_data.info = info;
	event_data.event_info.signal_data.ka = ka;

	record_event_all_consumers(PPME_SIGNALDELIVER_E, UF_USED | UF_ALWAYS_DROP, &event_data);
}
#endif

#ifdef CAPTURE_PAGE_FAULTS
TRACEPOINT_PROBE(page_fault_probe, unsigned long address, struct pt_regs *regs, unsigned long error_code)
{
	struct event_data_t event_data;

	/* We register both tracepoints under the same probe and
	 * sysdig event since there's little reason to expose this
	 * complexity to the sysdig user. The distinction can still be made
	 * in the output by looking for the USER_FAULT/SUPERVISOR_FAULT
	 * flags
	 */
	g_n_tracepoint_hit_inc();

	/* I still haven't decided if I'm interested in kernel threads or not.
	 * For the moment, I assume yes since I can see some value for it.
	 */

	event_data.category = PPMC_PAGE_FAULT;
	event_data.event_info.fault_data.address = address;
	event_data.event_info.fault_data.regs = regs;
	event_data.event_info.fault_data.error_code = error_code;

	record_event_all_consumers(PPME_PAGE_FAULT_E, UF_ALWAYS_DROP, &event_data);
}
#endif

static int init_ring_buffer(struct ppm_ring_buffer_context *ring)
{
	unsigned int j;

	/*
	 * Allocate the string storage in the ring descriptor
	 */
	ring->str_storage = (char *)__get_free_page(GFP_USER);
	if (!ring->str_storage) {
		pr_err("Error allocating the string storage\n");
		goto init_ring_err;
	}

	/*
	 * Allocate the buffer.
	 * Note how we allocate 2 additional pages: they are used as additional overflow space for
	 * the event data generation functions, so that they always operate on a contiguous buffer.
	 */
	ring->buffer = vmalloc(RING_BUF_SIZE + 2 * PAGE_SIZE);
	if (ring->buffer == NULL) {
		pr_err("Error allocating ring memory\n");
		goto init_ring_err;
	}

	for (j = 0; j < RING_BUF_SIZE + 2 * PAGE_SIZE; j++)
		ring->buffer[j] = 0;

	/*
	 * Allocate the buffer info structure
	 */
	ring->info = vmalloc(sizeof(struct ppm_ring_buffer_info));
	if (ring->info == NULL) {
		pr_err("Error allocating ring memory\n");
		goto init_ring_err;
	}

	/*
	 * Initialize the buffer info structure
	 */
	reset_ring_buffer(ring);
	atomic_set(&ring->preempt_count, 0);

	pr_info("CPU buffer initialized, size=%d\n", RING_BUF_SIZE);

	return 1;

init_ring_err:
	free_ring_buffer(ring);
	return 0;
}

static void free_ring_buffer(struct ppm_ring_buffer_context *ring)
{
	if (ring->info) {
		vfree(ring->info);
		ring->info = NULL;
	}

	if (ring->buffer) {
		vfree((void *)ring->buffer);
		ring->buffer = NULL;
	}

	if (ring->str_storage) {
		free_page((unsigned long)ring->str_storage);
		ring->str_storage = NULL;
	}
}

static void reset_ring_buffer(struct ppm_ring_buffer_context *ring)
{
	/*
	 * ring->preempt_count is not reset to 0 on purpose, to prevent a race condition
	 * see ppm_open
	 */
	ring->open = false;
	ring->capture_enabled = false;
	ring->info->head = 0;
	ring->info->tail = 0;
	ring->nevents = 0;
	ring->info->n_evts = 0;
	ring->info->n_drops_buffer = 0;
	ring->info->n_drops_pf = 0;
	ring->info->n_preemptions = 0;
	ring->info->n_context_switches = 0;
	ring->last_print_time = ppm_nsecs();
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
static void visit_tracepoint(struct tracepoint *tp, void *priv)
{
	if (!strcmp(tp->name, "sys_enter"))
		tp_sys_enter = tp;
	else if (!strcmp(tp->name, "sys_exit"))
		tp_sys_exit = tp;
	else if (!strcmp(tp->name, "sched_process_exit"))
		tp_sched_process_exit = tp;
#ifdef CAPTURE_CONTEXT_SWITCHES
	else if (!strcmp(tp->name, "sched_switch"))
		tp_sched_switch = tp;
#endif
#ifdef CAPTURE_SIGNAL_DELIVERIES
	else if (!strcmp(tp->name, "signal_deliver"))
		tp_signal_deliver = tp;
#endif
#ifdef CAPTURE_PAGE_FAULTS
	else if (!strcmp(tp->name, "page_fault_user"))
		tp_page_fault_user = tp;
	else if (!strcmp(tp->name, "page_fault_kernel"))
		tp_page_fault_kernel = tp;
#endif
}

static int get_tracepoint_handles(void)
{
	for_each_kernel_tracepoint(visit_tracepoint, NULL);

	if (!tp_sys_enter) {
		pr_err("failed to find sys_enter tracepoint\n");
		return -ENOENT;
	}
	if (!tp_sys_exit) {
		pr_err("failed to find sys_exit tracepoint\n");
		return -ENOENT;
	}
	if (!tp_sched_process_exit) {
		pr_err("failed to find sched_process_exit tracepoint\n");
		return -ENOENT;
	}
#ifdef CAPTURE_CONTEXT_SWITCHES
	if (!tp_sched_switch) {
		pr_err("failed to find sched_switch tracepoint\n");
		return -ENOENT;
	}
#endif
#ifdef CAPTURE_SIGNAL_DELIVERIES
	if (!tp_signal_deliver) {
		pr_err("failed to find signal_deliver tracepoint\n");
		return -ENOENT;
	}
#endif
#ifdef CAPTURE_PAGE_FAULTS
	if (!tp_page_fault_user) {
		pr_notice("failed to find page_fault_user tracepoint, disabling page-faults\n");
		g_fault_tracepoint_disabled = true;
	}
	if (!tp_page_fault_kernel) {
		pr_notice("failed to find page_fault_kernel tracepoint, disabling page-faults\n");
		g_fault_tracepoint_disabled = true;
	}
#endif

	return 0;
}
#else
static int get_tracepoint_handles(void)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
static char *ppm_devnode(struct device *dev, umode_t *mode)
#else
static char *ppm_devnode(struct device *dev, mode_t *mode)
#endif
{
	if (mode) {
		*mode = 0400;

		if (dev)
			if (MINOR(dev->devt) == g_ppm_numdevs)
				*mode = 0222;
	}

	return NULL;
}
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20) */

static int do_cpu_callback(unsigned long cpu, long sd_action)
{
	struct ppm_ring_buffer_context *ring;
	struct ppm_consumer_t *consumer;
	struct event_data_t event_data;

	if (sd_action != 0) {
		rcu_read_lock();

		list_for_each_entry_rcu(consumer, &g_consumer_list, node) {
			ring = per_cpu_ptr(consumer->ring_buffers, cpu);
			if (sd_action == 1) {
				/*
				 * If the cpu was offline when the consumer was created,
				 * this won't do anything because we never created a ring
				 * buffer. We can't safely create one here because we're
				 * in atomic context, and the consumer needs to call open
				 * on this device anyways, so do it in ppm_open.
				 */
				ring->cpu_online = true;
			} else if (sd_action == 2) {
				ring->cpu_online = false;
			}
		}

		rcu_read_unlock();

		event_data.category = PPMC_CONTEXT_SWITCH;
		event_data.event_info.context_data.sched_prev = (void *)cpu;
		event_data.event_info.context_data.sched_next = (void *)sd_action;
		record_event_all_consumers(PPME_CPU_HOTPLUG_E, UF_NEVER_DROP, &event_data);
	}
	return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0))
static int sysdig_cpu_online(unsigned int cpu)
{
	vpr_info("sysdig_cpu_online on cpu %d\n", cpu);
	return do_cpu_callback(cpu, 1);
}

static int sysdig_cpu_offline(unsigned int cpu)
{
	vpr_info("sysdig_cpu_offline on cpu %d\n", cpu);
	return do_cpu_callback(cpu, 2);
}
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)) */
/*
 * This gets called every time a CPU is added or removed
 */
static int cpu_callback(struct notifier_block *self, unsigned long action,
			void *hcpu)
{
	unsigned long cpu = (unsigned long)hcpu;
	long sd_action = 0;

	switch (action) {
	case CPU_UP_PREPARE:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	case CPU_UP_PREPARE_FROZEN:
#endif
		sd_action = 1;
		break;
	case CPU_DOWN_PREPARE:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	case CPU_DOWN_PREPARE_FROZEN:
#endif
		sd_action = 2;
		break;
	default:
		break;
	}

	if (do_cpu_callback(cpu, sd_action) < 0)
		return NOTIFY_BAD;
	else
		return NOTIFY_OK;
}

static struct notifier_block cpu_notifier = {
	.notifier_call = &cpu_callback,
	.next = NULL,
};
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0) */

int sysdig_init(void)
{
	dev_t dev;
	unsigned int cpu;
	unsigned int num_cpus;
	int ret;
	int acrret = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0))
	int hp_ret;
#endif
	int j;
	int n_created_devices = 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	struct device *device = NULL;
#else
	struct class_device *device = NULL;
#endif
	pr_info("driver loading, " PROBE_NAME " " PROBE_VERSION "\n");

	ret = get_tracepoint_handles();
	if (ret < 0)
		goto init_module_err;

	num_cpus = 0;
	for_each_possible_cpu(cpu) {
		++num_cpus;
	}

	/*
	 * Initialize the user I/O
	 * ( + 1 for sysdig-events)
	 */
	acrret = alloc_chrdev_region(&dev, 0, num_cpus + 1, PROBE_DEVICE_NAME);
	if (acrret < 0) {
		pr_err("could not allocate major number for %s\n", PROBE_DEVICE_NAME);
		ret = -ENOMEM;
		goto init_module_err;
	}

	g_ppm_class = class_create(THIS_MODULE, PROBE_DEVICE_NAME);
	if (IS_ERR(g_ppm_class)) {
		pr_err("can't allocate device class\n");
		ret = -EFAULT;
		goto init_module_err;
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	g_ppm_class->devnode = ppm_devnode;
#endif

	g_ppm_major = MAJOR(dev);
	g_ppm_numdevs = num_cpus;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
	g_ppm_devs = kmalloc(g_ppm_numdevs * sizeof(struct ppm_device), GFP_KERNEL);
#else
	g_ppm_devs = kmalloc_array(g_ppm_numdevs, sizeof(struct ppm_device), GFP_KERNEL);
#endif
	if (!g_ppm_devs) {
		pr_err("can't allocate devices\n");
		ret = -ENOMEM;
		goto init_module_err;
	}

	/*
	 * We create a unique user level device for each of the ring buffers
	 */
	for (j = 0; j < g_ppm_numdevs; ++j) {
		cdev_init(&g_ppm_devs[j].cdev, &g_ppm_fops);
		g_ppm_devs[j].dev = MKDEV(g_ppm_major, j);

		if (cdev_add(&g_ppm_devs[j].cdev, g_ppm_devs[j].dev, 1) < 0) {
			pr_err("could not allocate chrdev for %s\n", PROBE_DEVICE_NAME);
			ret = -EFAULT;
			goto init_module_err;
		}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		device = device_create(
#else
		device = class_device_create(
#endif
						g_ppm_class, NULL, /* no parent device */
						g_ppm_devs[j].dev,
						NULL, /* no additional data */
						PROBE_DEVICE_NAME "%d",
						j);

		if (IS_ERR(device)) {
			pr_err("error creating the device for  %s\n", PROBE_DEVICE_NAME);
			cdev_del(&g_ppm_devs[j].cdev);
			ret = -EFAULT;
			goto init_module_err;
		}

		init_waitqueue_head(&g_ppm_devs[j].read_queue);
		n_created_devices++;
	}

	/* create_proc_read_entry(PPM_DEVICE_NAME, 0, NULL, ppm_read_proc, NULL); */

	/*
	 * Snaplen lookahead initialization
	 */
	if (dpi_lookahead_init() != PPM_SUCCESS) {
		pr_err("initializing lookahead-based snaplen failed\n");
		ret = -EFAULT;
		goto init_module_err;
	}

	/*
	 * Set up our callback in case we get a hotplug even while we are
	 * initializing the cpu structures
	 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0))
	hp_ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
					   "sysdig/probe:online",
					   sysdig_cpu_online,
					   sysdig_cpu_offline);
	if (hp_ret <= 0) {
		pr_err("error registering cpu hotplug callback\n");
		ret = hp_ret;
		goto init_module_err;
	}
	hp_state = hp_ret;
#else
	register_cpu_notifier(&cpu_notifier);
#endif

	/*
	 * All ok. Final initializations.
	 */
	g_tracepoint_registered = false;

	return 0;

init_module_err:
	for (j = 0; j < n_created_devices; ++j) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		device_destroy(
#else
		class_device_destroy(
#endif
				g_ppm_class, g_ppm_devs[j].dev);

		cdev_del(&g_ppm_devs[j].cdev);
	}

	if (g_ppm_class)
		class_destroy(g_ppm_class);

	if (acrret == 0)
		unregister_chrdev_region(dev, g_ppm_numdevs);

	kfree(g_ppm_devs);

	return ret;
}

void sysdig_exit(void)
{
	int j;

	pr_info("driver unloading\n");

	for (j = 0; j < g_ppm_numdevs; ++j) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		device_destroy(
#else
		class_device_destroy(
#endif
				g_ppm_class, g_ppm_devs[j].dev);
		cdev_del(&g_ppm_devs[j].cdev);
	}

	if (g_ppm_class)
		class_destroy(g_ppm_class);

	/* + 1 for sysdig-events */
	unregister_chrdev_region(MKDEV(g_ppm_major, 0), g_ppm_numdevs + 1);

	kfree(g_ppm_devs);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	tracepoint_synchronize_unregister();
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0))
	if (hp_state > 0)
		cpuhp_remove_state_nocalls(hp_state);
#else
	unregister_cpu_notifier(&cpu_notifier);
#endif
}

module_init(sysdig_init);
module_exit(sysdig_exit);
module_param(max_consumers, uint, 0444);
MODULE_PARM_DESC(max_consumers, "Maximum number of consumers that can simultaneously open the devices");
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
module_param(verbose, bool, 0444);
#endif
MODULE_PARM_DESC(verbose, "Enable verbose logging");
