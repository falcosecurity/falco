/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/compat.h>
#include <linux/cdev.h>
#include <asm/unistd.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <net/compat.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/quota.h>
#include <linux/tty.h>
#include <linux/uaccess.h>
#include <linux/audit.h>
#ifdef CONFIG_CGROUPS
#include <linux/cgroup.h>
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20)
#include "ppm_syscall.h"
#else
#include <asm/syscall.h>
#endif

#include "ppm_ringbuffer.h"
#include "ppm_events_public.h"
#include "ppm_events.h"
#include "ppm.h"
#include "ppm_flag_helpers.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
#include <linux/bpf.h>
#endif

/*
 * Linux 5.6 kernels no longer include the old 32-bit timeval
 * structures. But the syscalls (might) still use them.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#include <linux/time64.h>
struct compat_timespec {
	int32_t tv_sec;
	int32_t tv_nsec;
};

struct timespec {
	int32_t tv_sec;
	int32_t tv_nsec;
};

struct timeval {
	int32_t tv_sec;
	int32_t tv_usec;
};
#else
#define timeval64 timeval
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
static inline struct inode *file_inode(struct file *f)
{
	return f->f_path.dentry->d_inode;
}
#endif

#define merge_64(hi, lo) ((((unsigned long long)(hi)) << 32) + ((lo) & 0xffffffffUL))

/*
 * Linux 5.1 kernels modify the syscall_get_arguments function to always
 * return all arguments rather than allowing the caller to select which
 * arguments are desired. This wrapper replicates the original
 * functionality.
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0))
#define syscall_get_arguments_deprecated syscall_get_arguments
#else
#define syscall_get_arguments_deprecated(_task, _reg, _start, _len, _args) \
	do { \
		unsigned long _sga_args[6] = {}; \
		syscall_get_arguments(_task, _reg, _sga_args); \
		memcpy(_args, &_sga_args[_start], _len * sizeof(unsigned long)); \
	} while(0)
#endif

static inline struct pid_namespace *pid_ns_for_children(struct task_struct *task)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))
	return task->nsproxy->pid_ns;
#else
	return task->nsproxy->pid_ns_for_children;
#endif
}

int f_sys_generic(struct event_filler_arguments *args)
{
	int res;
	long table_index = args->syscall_id - SYSCALL_TABLE_ID0;
	const enum ppm_syscall_code *cur_g_syscall_code_routing_table = args->cur_g_syscall_code_routing_table;

#ifdef _HAS_SOCKETCALL
	if (unlikely(args->syscall_id == args->socketcall_syscall)) {
		/*
		 * All the socket calls should be implemented
		 */
		ASSERT(false);
		return PPM_FAILURE_BUG;
	}
#endif

	/*
	 * name
	 */

	if (likely(table_index >= 0 &&
		   table_index <  SYSCALL_TABLE_SIZE)) {
		enum ppm_syscall_code sc_code = cur_g_syscall_code_routing_table[table_index];

		/*
		 * ID
		 */
		res = val_to_ring(args, sc_code, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		if (args->event_type == PPME_GENERIC_E) {
			/*
			 * nativeID
			 */
			res = val_to_ring(args, args->syscall_id, 0, false, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		}
	} else {
		ASSERT(false);
		res = val_to_ring(args, (unsigned long)"<out of bound>", 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	return add_sentinel(args);
}

int f_sys_empty(struct event_filler_arguments *args)
{
	return add_sentinel(args);
}

int f_sys_single(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;

	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_single_x(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;

	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static inline uint32_t get_fd_dev(int64_t fd)
{
	struct files_struct *files;
	struct fdtable *fdt;
	struct file *file;
	struct inode *inode;
	struct super_block *sb;
	uint32_t dev = 0;

	if (fd < 0)
		return dev;

	files = current->files;
	if (unlikely(!files))
		return dev;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (unlikely(fd > fdt->max_fds))
		goto out_unlock;

	file = fdt->fd[fd];
	if (unlikely(!file))
		goto out_unlock;

	inode = file_inode(file);
	if (unlikely(!inode))
		goto out_unlock;

	sb = inode->i_sb;
	if (unlikely(!sb))
		goto out_unlock;

	dev = new_encode_dev(sb->s_dev);

out_unlock:
	spin_unlock(&files->file_lock);
	return dev;
}

int f_sys_open_x(struct event_filler_arguments *args)
{
	unsigned long val;
	unsigned long flags;
	unsigned long modes;
	int res;
	int64_t retval;

	/*
	 * fd
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Flags
	 * Note that we convert them into the ppm portable representation before pushing them to the ring
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &flags);
	res = val_to_ring(args, open_flags_to_scap(flags), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 *  mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &modes);
	res = val_to_ring(args, open_modes_to_scap(flags, modes), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * dev
	 */
	res = val_to_ring(args, get_fd_dev(retval), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_read_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long bufsize;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	args->fd = (int)val;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * data
	 */
	if (retval < 0) {
		/*
		 * The operation failed, return an empty buffer
		 */
		val = 0;
		bufsize = 0;
	} else {
		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);

		/*
		 * The return value can be lower than the value provided by the user,
		 * and we take that into account.
		 */
		bufsize = retval;
	}

	/*
	 * Copy the buffer
	 */
	args->enforce_snaplen = true;
	res = val_to_ring(args, val, bufsize, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_write_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long bufsize;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	args->fd = (int)val;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);

	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * data
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	bufsize = val;

	/*
	 * Copy the buffer
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	args->enforce_snaplen = true;
	res = val_to_ring(args, val, bufsize, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

/*
 * get_mm_counter was not inline and exported between 3.0 and 3.4
 * https://github.com/torvalds/linux/commit/69c978232aaa99476f9bd002c2a29a84fa3779b5
 * Hence the crap in these two functions
 */
unsigned long ppm_get_mm_counter(struct mm_struct *mm, int member)
{
	long val = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	val = get_mm_counter(mm, member);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	val = atomic_long_read(&mm->rss_stat.count[member]);

	if (val < 0)
		val = 0;
#endif

	return val;
}

static unsigned long ppm_get_mm_swap(struct mm_struct *mm)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	return ppm_get_mm_counter(mm, MM_SWAPENTS);
#endif
	return 0;
}

static unsigned long ppm_get_mm_rss(struct mm_struct *mm)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	return get_mm_rss(mm);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	return ppm_get_mm_counter(mm, MM_FILEPAGES) +
		ppm_get_mm_counter(mm, MM_ANONPAGES);
#else
	return get_mm_rss(mm);
#endif
	return 0;
}

#ifdef CONFIG_CGROUPS
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
static int ppm_cgroup_path(const struct cgroup *cgrp, char *buf, int buflen)
{
	char *start;
	struct dentry *dentry = rcu_dereference(cgrp->dentry);

	if (!dentry) {
		/*
		 * Inactive subsystems have no dentry for their root
		 * cgroup
		 */
		strcpy(buf, "/");
		return 0;
	}

	start = buf + buflen;

	*--start = '\0';
	for (;;) {
		int len = dentry->d_name.len;

		start -= len;
		if (start < buf)
			return -ENAMETOOLONG;
		memcpy(start, cgrp->dentry->d_name.name, len);
		cgrp = cgrp->parent;
		if (!cgrp)
			break;
		dentry = rcu_dereference(cgrp->dentry);
		if (!cgrp->parent)
			continue;
		if (--start < buf)
			return -ENAMETOOLONG;
		*start = '/';
	}
	memmove(buf, start, buf + buflen - start);
	return 0;
}
#endif

static int append_cgroup(const char *subsys_name, int subsys_id, char *buf, int *available)
{
	int pathlen;
	int subsys_len;
	char *path;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0) || LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	int res;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	struct cgroup_subsys_state *css = task_css(current, subsys_id);
#else
	struct cgroup_subsys_state *css = task_subsys_state(current, subsys_id);
#endif

	if (!css) {
		ASSERT(false);
		return 1;
	}

	if (!css->cgroup) {
		ASSERT(false);
		return 1;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	// According to https://github.com/torvalds/linux/commit/4c737b41de7f4eef2a593803bad1b918dd718b10
	// cgroup_path now returns an int again
	res = cgroup_path(css->cgroup, buf, *available);
	if (res < 0) {
		ASSERT(false);
		path = "NA";
	} else {
		path = buf;
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
	path = cgroup_path(css->cgroup, buf, *available);
	if (!path) {
		ASSERT(false);
		path = "NA";
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	res = cgroup_path(css->cgroup, buf, *available);
	if (res < 0) {
		ASSERT(false);
		path = "NA";
	} else {
		path = buf;
	}
#else
	res = ppm_cgroup_path(css->cgroup, buf, *available);
	if (res < 0) {
		ASSERT(false);
		path = "NA";
	} else {
		path = buf;
	}
#endif

	pathlen = strlen(path);
	subsys_len = strlen(subsys_name);
	if (subsys_len + 1 + pathlen + 1 > *available)
		return 1;

	memmove(buf + subsys_len + 1, path, pathlen);
	memcpy(buf, subsys_name, subsys_len);
	buf += subsys_len;
	*buf++ = '=';
	buf += pathlen;
	*buf++ = 0;
	*available -= (subsys_len + 1 + pathlen + 1);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
#define SUBSYS(_x)																						\
if (append_cgroup(#_x, _x ## _cgrp_id, args->str_storage + STR_STORAGE_SIZE - available, &available))	\
	goto cgroups_error;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define IS_SUBSYS_ENABLED(option) IS_BUILTIN(option)
#define SUBSYS(_x)																						\
if (append_cgroup(#_x, _x ## _subsys_id, args->str_storage + STR_STORAGE_SIZE - available, &available)) \
	goto cgroups_error;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#define IS_SUBSYS_ENABLED(option) IS_ENABLED(option)
#define SUBSYS(_x)																						\
if (append_cgroup(#_x, _x ## _subsys_id, args->str_storage + STR_STORAGE_SIZE - available, &available)) \
	goto cgroups_error;
#else
#define SUBSYS(_x)																						\
if (append_cgroup(#_x, _x ## _subsys_id, args->str_storage + STR_STORAGE_SIZE - available, &available)) \
	goto cgroups_error;
#endif

#endif

/* Takes in a NULL-terminated array of pointers to strings in userspace, and
 * concatenates them to a single \0-separated string. Return the length of this
 * string, or <0 on error */
static int accumulate_argv_or_env(const char __user * __user *argv,
				  char *str_storage,
				  int available)
{
	int len = 0;
	int n_bytes_copied;

	if (argv == NULL)
		return len;

	for (;;) {
		const char __user *p;

		if (unlikely(ppm_get_user(p, argv)))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		if (p == NULL)
			break;

		/* need at least enough space for a \0 */
		if (available < 1)
			return PPM_FAILURE_BUFFER_FULL;

		n_bytes_copied = ppm_strncpy_from_user(&str_storage[len], p,
						       available);

		/* ppm_strncpy_from_user includes the trailing \0 in its return
		 * count. I want to pretend it was strncpy_from_user() so I
		 * subtract off the 1 */
		n_bytes_copied--;

		if (n_bytes_copied < 0)
			return PPM_FAILURE_INVALID_USER_MEMORY;

		if (n_bytes_copied >= available)
			return PPM_FAILURE_BUFFER_FULL;

		/* update buffer. I want to keep the trailing \0, so I +1 */
		available   -= n_bytes_copied+1;
		len         += n_bytes_copied+1;

		argv++;
	}

	return len;
}

#ifdef CONFIG_COMPAT
/* compat version that deals correctly with 32bits pointers of argv */
static int compat_accumulate_argv_or_env(compat_uptr_t argv,
				  char *str_storage,
				  int available)
{
	int len = 0;
	int n_bytes_copied;

	if (compat_ptr(argv) == NULL)
		return len;

	for (;;) {
		compat_uptr_t compat_p;
		const char __user *p;

		if (unlikely(ppm_get_user(compat_p, compat_ptr(argv))))
			return PPM_FAILURE_INVALID_USER_MEMORY;
		p = compat_ptr(compat_p);

		if (p == NULL)
			break;

		/* need at least enough space for a \0 */
		if (available < 1)
			return PPM_FAILURE_BUFFER_FULL;

		n_bytes_copied = ppm_strncpy_from_user(&str_storage[len], p,
						       available);

		/* ppm_strncpy_from_user includes the trailing \0 in its return
		 * count. I want to pretend it was strncpy_from_user() so I
		 * subtract off the 1 */
		n_bytes_copied--;

		if (n_bytes_copied < 0) {
			return PPM_FAILURE_INVALID_USER_MEMORY;
		}
		if (n_bytes_copied >= available)
			return PPM_FAILURE_BUFFER_FULL;

		/* update buffer. I want to keep the trailing \0, so I +1 */
		available   -= n_bytes_copied+1;
		len         += n_bytes_copied+1;

		argv += sizeof(compat_uptr_t);
	}

	return len;
}

#endif

// probe_kernel_read() only added in kernel 2.6.26
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
long probe_kernel_read(void *dst, const void *src, size_t size)
{
	long ret;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	pagefault_disable();
	ret = __copy_from_user_inatomic(dst, (__force const void __user *)src, size);
	pagefault_enable();
	set_fs(old_fs);

	return ret ? -EFAULT : 0;
}
#endif

static int ppm_get_tty(void)
{
	/* Locking of the signal structures seems too complicated across
	 * multiple kernel versions to get it right, so simply do protected
	 * memory accesses, and in the worst case we get some garbage,
	 * which is not the end of the world. In the vast majority of accesses,
	 * we'll be just fine.
	 */
	struct signal_struct *sig;
	struct tty_struct *tty;
	struct tty_driver *driver;
	int major;
	int minor_start;
	int index;
	int tty_nr = 0;

	sig = current->signal;
	if (!sig)
		return 0;

	if (unlikely(probe_kernel_read(&tty, &sig->tty, sizeof(tty))))
		return 0;

	if (!tty)
		return 0;

	if (unlikely(probe_kernel_read(&index, &tty->index, sizeof(index))))
		return 0;

	if (unlikely(probe_kernel_read(&driver, &tty->driver, sizeof(driver))))
		return 0;

	if (!driver)
		return 0;

	if (unlikely(probe_kernel_read(&major, &driver->major, sizeof(major))))
		return 0;

	if (unlikely(probe_kernel_read(&minor_start, &driver->minor_start, sizeof(minor_start))))
		return 0;

	tty_nr = new_encode_dev(MKDEV(major, minor_start) + index);

	return tty_nr;
}

int f_proc_startupdate(struct event_filler_arguments *args)
{
	unsigned long val;
	int res = 0;
	unsigned int exe_len = 0;  /* the length of the executable string */
	int args_len = 0; /*the combined length of the arguments string + executable string */
	struct mm_struct *mm = current->mm;
	int64_t retval;
	int ptid;
	char *spwd = "";
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;
	int available = STR_STORAGE_SIZE;

	/*
	 * Make sure the operation was successful
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	if (unlikely(retval < 0 &&
		     args->event_type != PPME_SYSCALL_EXECVE_19_X)) {

		/* The call failed, but this syscall has no exe, args
		 * anyway, so I report empty ones */
		*args->str_storage = 0;

		/*
		 * exe
		 */
		res = val_to_ring(args, (uint64_t)(long)args->str_storage, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		/*
		 * Args
		 */
		res = val_to_ring(args, (int64_t)(long)args->str_storage, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {

		if (likely(retval >= 0)) {
			/*
			 * The call succeeded. Get exe, args from the current
			 * process; put one \0-separated exe-args string into
			 * str_storage
			 */

			if (unlikely(!mm)) {
				args->str_storage[0] = 0;
				pr_info("f_proc_startupdate drop, mm=NULL\n");
				return PPM_FAILURE_BUG;
			}

			if (unlikely(!mm->arg_end)) {
				args->str_storage[0] = 0;
				pr_info("f_proc_startupdate drop, mm->arg_end=NULL\n");
				return PPM_FAILURE_BUG;
			}

			args_len = mm->arg_end - mm->arg_start;

			if (args_len) {
				if (args_len > PAGE_SIZE)
					args_len = PAGE_SIZE;

				if (unlikely(ppm_copy_from_user(args->str_storage, (const void __user *)mm->arg_start, args_len)))
					args_len = 0;
				else
					args->str_storage[args_len - 1] = 0;
			}
		} else {

			/*
			 * The execve call failed. I get exe, args from the
			 * input args; put one \0-separated exe-args string into
			 * str_storage
			 */
			args->str_storage[0] = 0;

			syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
#ifdef CONFIG_COMPAT
			if (unlikely(args->compat))
				args_len = compat_accumulate_argv_or_env((compat_uptr_t)val,
							   args->str_storage, available);
			else
#endif
				args_len = accumulate_argv_or_env((const char __user * __user *)val,
							   args->str_storage, available);

			if (unlikely(args_len < 0))
				args_len = 0;
		}

		if (args_len == 0)
			*args->str_storage = 0;

		exe_len = strnlen(args->str_storage, args_len);
		if (exe_len < args_len)
			++exe_len;

		/*
		 * exe
		 */
		res = val_to_ring(args, (uint64_t)(long)args->str_storage, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		/*
		 * Args
		 */
		res = val_to_ring(args, (int64_t)(long)args->str_storage + exe_len, args_len - exe_len, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}


	/*
	 * tid
	 */
	res = val_to_ring(args, (int64_t)current->pid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pid
	 */
	res = val_to_ring(args, (int64_t)current->tgid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * ptid
	 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	if (current->real_parent)
		ptid = current->real_parent->pid;
#else
	if (current->parent)
		ptid = current->parent->pid;
#endif
	else
		ptid = 0;

	res = val_to_ring(args, (int64_t)ptid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * cwd, pushed empty to avoid breaking compatibility
	 * with the older event format
	 */
	res = val_to_ring(args, (uint64_t)(long)spwd, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * fdlimit
	 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	res = val_to_ring(args, (int64_t)rlimit(RLIMIT_NOFILE), 0, false, 0);
#else
	res = val_to_ring(args, (int64_t)0, 0, false, 0);
#endif
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * pgft_maj
	 */
	res = val_to_ring(args, current->maj_flt, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pgft_min
	 */
	res = val_to_ring(args, current->min_flt, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	if (mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT-10);
		total_rss = ppm_get_mm_rss(mm) << (PAGE_SHIFT-10);
		swap = ppm_get_mm_swap(mm) << (PAGE_SHIFT-10);
	}

	/*
	 * vm_size
	 */
	res = val_to_ring(args, total_vm, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * vm_rss
	 */
	res = val_to_ring(args, total_rss, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * vm_swap
	 */
	res = val_to_ring(args, swap, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * comm
	 */
	res = val_to_ring(args, (uint64_t)current->comm, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * cgroups
	 */
	args->str_storage[0] = 0;
#ifdef CONFIG_CGROUPS
	rcu_read_lock();
#include <linux/cgroup_subsys.h>
cgroups_error:
	rcu_read_unlock();
#endif

	res = val_to_ring(args, (int64_t)(long)args->str_storage, STR_STORAGE_SIZE - available, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	if (args->event_type == PPME_SYSCALL_CLONE_20_X ||
		args->event_type == PPME_SYSCALL_FORK_20_X ||
		args->event_type == PPME_SYSCALL_VFORK_20_X) {
		/*
		 * clone-only parameters
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		uint64_t euid = from_kuid_munged(current_user_ns(), current_euid());
		uint64_t egid = from_kgid_munged(current_user_ns(), current_egid());
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		uint64_t euid = current_euid();
		uint64_t egid = current_egid();
#else
		uint64_t euid = current->euid;
		uint64_t egid = current->egid;
#endif
		int64_t in_pidns = 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		struct pid_namespace *pidns = task_active_pid_ns(current);
#endif

		/*
		 * flags
		 */
		if (args->event_type == PPME_SYSCALL_CLONE_20_X) {
#ifdef CONFIG_S390
			syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
#else
			syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
#endif
		} else
			val = 0;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		if(pidns != &init_pid_ns || pid_ns_for_children(current) != pidns)
			in_pidns = PPM_CL_CHILD_IN_PIDNS;
#endif
		res = val_to_ring(args, (uint64_t)clone_flags_to_scap(val) | in_pidns, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		/*
		 * uid
		 */
		res = val_to_ring(args, euid, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		/*
		 * gid
		 */
		res = val_to_ring(args, egid, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		/*
		 * vtid
		 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		res = val_to_ring(args, task_pid_vnr(current), 0, false, 0);
#else
		/* Not relevant in old kernels */
		res = val_to_ring(args, 0, 0, false, 0);
#endif
		if (unlikely(res != PPM_SUCCESS))
			return res;

		/*
		 * vpid
		 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		res = val_to_ring(args, task_tgid_vnr(current), 0, false, 0);
#else
		/* Not relevant in old kernels */
		res = val_to_ring(args, 0, 0, false, 0);
#endif
		if (unlikely(res != PPM_SUCCESS))
			return res;

	} else if (args->event_type == PPME_SYSCALL_EXECVE_19_X) {
		/*
		 * execve-only parameters
		 */
		long env_len = 0;
		int tty_nr = 0;

		if (likely(retval >= 0)) {
			/*
			 * Already checked for mm validity
			 */
			env_len = mm->env_end - mm->env_start;

			if (env_len) {
				if (env_len > PAGE_SIZE)
					env_len = PAGE_SIZE;

				if (unlikely(ppm_copy_from_user(args->str_storage, (const void __user *)mm->env_start, env_len)))
					env_len = 0;
				else
					args->str_storage[env_len - 1] = 0;
			}
		} else {
			/*
			 * The call failed, so get the env from the arguments
			 */
			syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
#ifdef CONFIG_COMPAT
			if (unlikely(args->compat))
				env_len = compat_accumulate_argv_or_env((compat_uptr_t)val,
							  args->str_storage, available);
			else
#endif
				env_len = accumulate_argv_or_env((const char __user * __user *)val,
							  args->str_storage, available);

			if (unlikely(env_len < 0))
				env_len = 0;
		}

		if (env_len == 0)
			*args->str_storage = 0;

		/*
		 * environ
		 */
		res = val_to_ring(args, (int64_t)(long)args->str_storage, env_len, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		/*
		 * tty
		 */
		tty_nr = ppm_get_tty();
		res = val_to_ring(args, tty_nr, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		/*
		 * pgid
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
		res = val_to_ring(args, (int64_t)task_pgrp_nr_ns(current, task_active_pid_ns(current)), 0, false, 0);
#else
		res = val_to_ring(args, (int64_t)process_group(current), 0, false, 0);
#endif
		if (unlikely(res != PPM_SUCCESS))
			return res;

		/*
	 	* loginuid
	 	*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		val = from_kuid(current_user_ns(), audit_get_loginuid(current));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
		val = audit_get_loginuid(current);
#else
		val = audit_get_loginuid(current->audit_context);
#endif
		res = val_to_ring(args, val, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	return add_sentinel(args);
}

int f_sys_execve_e(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;

	/*
	 * filename
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (res == PPM_FAILURE_INVALID_USER_MEMORY)
		res = val_to_ring(args, (unsigned long)"<NA>", 0, false, 0);

	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_socket_bind_x(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	int err = 0;
	u16 size = 0;
	struct sockaddr __user *usrsockaddr;
	unsigned long val;
	struct sockaddr_storage address;
	char *targetbuf = args->str_storage;

	/*
	 * res
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);

	/*
	 * addr
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	else
		val = args->socketcall_args[1];

	usrsockaddr = (struct sockaddr __user *)val;

	/*
	 * Get the address len
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	else
		val = args->socketcall_args[2];

	if (usrsockaddr != NULL && val != 0) {
		/*
		 * Copy the address
		 */
		err = addr_to_kernel(usrsockaddr, val, (struct sockaddr *)&address);
		if (likely(err >= 0)) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = pack_addr((struct sockaddr *)&address,
				val,
				targetbuf,
				STR_STORAGE_SIZE);
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_connect_x(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	int err = 0;
	int fd;
	struct sockaddr __user *usrsockaddr;
	u16 size = 0;
	char *targetbuf = args->str_storage;
	struct sockaddr_storage address;
	unsigned long val;

	/*
	 * Push the result
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);

	/*
	 * Retrieve the fd and push it to the ring.
	 * Note that, even if we are in the exit callback, the arguments are still
	 * in the stack, and therefore we can consume them.
	 */
	if (!args->is_socketcall) {
		syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
		fd = (int)val;
	} else
		fd = (int)args->socketcall_args[0];

	if (fd >= 0) {
		/*
		 * Get the address
		 */
		if (!args->is_socketcall)
			syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
		else
			val = args->socketcall_args[1];

		usrsockaddr = (struct sockaddr __user *)val;

		/*
		 * Get the address len
		 */
		if (!args->is_socketcall)
			syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
		else
			val = args->socketcall_args[2];

		if (usrsockaddr != NULL && val != 0) {
			/*
			 * Copy the address
			 */
			err = addr_to_kernel(usrsockaddr, val, (struct sockaddr *)&address);
			if (likely(err >= 0)) {
				/*
				 * Convert the fd into socket endpoint information
				 */
				size = fd_to_socktuple(fd,
					(struct sockaddr *)&address,
					val,
					true,
					false,
					targetbuf,
					STR_STORAGE_SIZE);
			}
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_socketpair_x(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	unsigned long val;
	int fds[2];
	int err;
	struct socket *sock;
	struct unix_sock *us;
	struct sock *speer;

	/*
	 * retval
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * If the call was successful, copy the FDs
	 */
	if (likely(retval >= 0)) {
		/*
		 * fds
		 */
		if (!args->is_socketcall)
			syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
		else
			val = args->socketcall_args[3];
#ifdef CONFIG_COMPAT
		if (!args->compat) {
#endif
			if (unlikely(ppm_copy_from_user(fds, (const void __user *)val, sizeof(fds))))
				return PPM_FAILURE_INVALID_USER_MEMORY;
#ifdef CONFIG_COMPAT
		} else {
			if (unlikely(ppm_copy_from_user(fds, (const void __user *)compat_ptr(val), sizeof(fds))))
				return PPM_FAILURE_INVALID_USER_MEMORY;
		}
#endif

		res = val_to_ring(args, fds[0], 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		res = val_to_ring(args, fds[1], 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		/* get socket source and peer address */
		sock = sockfd_lookup(fds[0], &err);
		if (likely(sock != NULL)) {
			us = unix_sk(sock->sk);
			speer = us->peer;
			res = val_to_ring(args, (unsigned long)us, 0, false, 0);
			if (unlikely(res != PPM_SUCCESS)) {
				sockfd_put(sock);
				return res;
			}

			res = val_to_ring(args, (unsigned long)speer, 0, false, 0);
			if (unlikely(res != PPM_SUCCESS)) {
				sockfd_put(sock);
				return res;
			}

			sockfd_put(sock);
		} else {
			return err;
		}
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	return add_sentinel(args);
}

static int parse_sockopt(struct event_filler_arguments *args, int level, int optname, const void __user *optval, int optlen)
{
	union {
		uint32_t val32;
		uint64_t val64;
		struct timeval tv;
	} u;
	nanoseconds ns = 0;

	if (level == SOL_SOCKET) {
		switch (optname) {
#ifdef SO_ERROR
			case SO_ERROR:
				if (unlikely(ppm_copy_from_user(&u.val32, optval, sizeof(u.val32))))
					return PPM_FAILURE_INVALID_USER_MEMORY;
				return val_to_ring(args, -(int)u.val32, 0, false, PPM_SOCKOPT_IDX_ERRNO);
#endif

#ifdef SO_RCVTIMEO
			case SO_RCVTIMEO:
#endif
#ifdef SO_SNDTIMEO
			case SO_SNDTIMEO:
#endif
				if (unlikely(ppm_copy_from_user(&u.tv, optval, sizeof(u.tv)))) {
					return PPM_FAILURE_INVALID_USER_MEMORY;
				}
				ns = u.tv.tv_sec * SECOND_IN_NS + u.tv.tv_usec * 1000;
				return val_to_ring(args, ns, 0, false, PPM_SOCKOPT_IDX_TIMEVAL);

#ifdef SO_COOKIE
			case SO_COOKIE:
				if (unlikely(ppm_copy_from_user(&u.val64, optval, sizeof(u.val64))))
					return PPM_FAILURE_INVALID_USER_MEMORY;
				return val_to_ring(args, u.val64, 0, false, PPM_SOCKOPT_IDX_UINT64);
#endif

#ifdef SO_DEBUG
			case SO_DEBUG:
#endif
#ifdef SO_REUSEADDR
			case SO_REUSEADDR:
#endif
#ifdef SO_TYPE
			case SO_TYPE:
#endif
#ifdef SO_DONTROUTE
			case SO_DONTROUTE:
#endif
#ifdef SO_BROADCAST
			case SO_BROADCAST:
#endif
#ifdef SO_SNDBUF
			case SO_SNDBUF:
#endif
#ifdef SO_RCVBUF
			case SO_RCVBUF:
#endif
#ifdef SO_SNDBUFFORCE
			case SO_SNDBUFFORCE:
#endif
#ifdef SO_RCVBUFFORCE
			case SO_RCVBUFFORCE:
#endif
#ifdef SO_KEEPALIVE
			case SO_KEEPALIVE:
#endif
#ifdef SO_OOBINLINE
			case SO_OOBINLINE:
#endif
#ifdef SO_NO_CHECK
			case SO_NO_CHECK:
#endif
#ifdef SO_PRIORITY
			case SO_PRIORITY:
#endif
#ifdef SO_BSDCOMPAT
			case SO_BSDCOMPAT:
#endif
#ifdef SO_REUSEPORT
			case SO_REUSEPORT:
#endif
#ifdef SO_PASSCRED
			case SO_PASSCRED:
#endif
#ifdef SO_RCVLOWAT
			case SO_RCVLOWAT:
#endif
#ifdef SO_SNDLOWAT
			case SO_SNDLOWAT:
#endif
#ifdef SO_SECURITY_AUTHENTICATION
			case SO_SECURITY_AUTHENTICATION:
#endif
#ifdef SO_SECURITY_ENCRYPTION_TRANSPORT
			case SO_SECURITY_ENCRYPTION_TRANSPORT:
#endif
#ifdef SO_SECURITY_ENCRYPTION_NETWORK
			case SO_SECURITY_ENCRYPTION_NETWORK:
#endif
#ifdef SO_BINDTODEVICE
			case SO_BINDTODEVICE:
#endif
#ifdef SO_DETACH_FILTER
			case SO_DETACH_FILTER:
#endif
#ifdef SO_TIMESTAMP
			case SO_TIMESTAMP:
#endif
#ifdef SO_ACCEPTCONN
			case SO_ACCEPTCONN:
#endif
#ifdef SO_PEERSEC
			case SO_PEERSEC:
#endif
#ifdef SO_PASSSEC
			case SO_PASSSEC:
#endif
#ifdef SO_TIMESTAMPNS
			case SO_TIMESTAMPNS:
#endif
#ifdef SO_MARK
			case SO_MARK:
#endif
#ifdef SO_TIMESTAMPING
			case SO_TIMESTAMPING:
#endif
#ifdef SO_PROTOCOL
			case SO_PROTOCOL:
#endif
#ifdef SO_DOMAIN
			case SO_DOMAIN:
#endif
#ifdef SO_RXQ_OVFL
			case SO_RXQ_OVFL:
#endif
#ifdef SO_WIFI_STATUS
			case SO_WIFI_STATUS:
#endif
#ifdef SO_PEEK_OFF
			case SO_PEEK_OFF:
#endif
#ifdef SO_NOFCS
			case SO_NOFCS:
#endif
#ifdef SO_LOCK_FILTER
			case SO_LOCK_FILTER:
#endif
#ifdef SO_SELECT_ERR_QUEUE
			case SO_SELECT_ERR_QUEUE:
#endif
#ifdef SO_BUSY_POLL
			case SO_BUSY_POLL:
#endif
#ifdef SO_MAX_PACING_RATE
			case SO_MAX_PACING_RATE:
#endif
#ifdef SO_BPF_EXTENSIONS
			case SO_BPF_EXTENSIONS:
#endif
#ifdef SO_INCOMING_CPU
			case SO_INCOMING_CPU:
#endif
				if (unlikely(ppm_copy_from_user(&u.val32, optval, sizeof(u.val32))))
					return PPM_FAILURE_INVALID_USER_MEMORY;
				return val_to_ring(args, u.val32, 0, false, PPM_SOCKOPT_IDX_UINT32);

			default:
				return val_to_ring(args, (unsigned long)optval, optlen, true, PPM_SOCKOPT_IDX_UNKNOWN);
		}
	} else {
		return val_to_ring(args, (unsigned long)optval, optlen, true, PPM_SOCKOPT_IDX_UNKNOWN);
	}
}

int f_sys_setsockopt_x(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	unsigned long val[5] = {};

	syscall_get_arguments_deprecated(current, args->regs, 0, 5, val);
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);

	/* retval */
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/* fd */
	res = val_to_ring(args, val[0], 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/* level */
	res = val_to_ring(args, sockopt_level_to_scap(val[1]), 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/* optname */
	res = val_to_ring(args, sockopt_optname_to_scap(val[1], val[2]), 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/* optval */
	res = parse_sockopt(args, val[1], val[2], (const void __user*)val[3], val[4]);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/* optlen */
	res = val_to_ring(args, val[4], 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);

}

int f_sys_getsockopt_x(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	uint32_t optlen;
	unsigned long val[5] = {};

	syscall_get_arguments_deprecated(current, args->regs, 0, 5, val);
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);

	/* retval */
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/* fd */
	res = val_to_ring(args, val[0], 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/* level */
	res = val_to_ring(args, sockopt_level_to_scap(val[1]), 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/* optname */
	res = val_to_ring(args, sockopt_optname_to_scap(val[1], val[2]), 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	if (unlikely(ppm_copy_from_user(&optlen, (const void __user*)val[4], sizeof(optlen))))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	/* optval */
	res = parse_sockopt(args, val[1], val[2], (const void __user*)val[3], optlen);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/* optlen */
	res = val_to_ring(args, optlen, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_accept4_e(struct event_filler_arguments *args)
{
	int res;

	/*
	 * push the flags into the ring.
	 * XXX we don't support flags yet and so we just return zero
	 */
	/* res = val_to_ring(args, args->socketcall_args[3]); */
	res = val_to_ring(args, 0, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_accept_x(struct event_filler_arguments *args)
{
	int res;
	int fd;
	char *targetbuf = args->str_storage;
	u16 size = 0;
	unsigned long queuepct = 0;
	unsigned long ack_backlog = 0;
	unsigned long max_ack_backlog = 0;
	unsigned long srvskfd;
	int err = 0;
	struct socket *sock;

	/*
	 * Push the fd
	 */
	fd = syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Convert the fd into socket endpoint information
	 */
	size = fd_to_socktuple(fd,
		NULL,
		0,
		false,
		true,
		targetbuf,
		STR_STORAGE_SIZE);

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * queuepct
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 0, 1, &srvskfd);
	else
		srvskfd = args->socketcall_args[0];

	sock = sockfd_lookup(srvskfd, &err);

	if (sock && sock->sk) {
		ack_backlog = sock->sk->sk_ack_backlog;
		max_ack_backlog = sock->sk->sk_max_ack_backlog;
	}

	if (sock)
		sockfd_put(sock);

	if (max_ack_backlog)
		queuepct = (unsigned long)ack_backlog * 100 / max_ack_backlog;

	res = val_to_ring(args, queuepct, 0, false, 0);
	if (res != PPM_SUCCESS)
		return res;

	res = val_to_ring(args, ack_backlog, 0, false, 0);
	if (res != PPM_SUCCESS)
		return res;

	res = val_to_ring(args, max_ack_backlog, 0, false, 0);
	if (res != PPM_SUCCESS)
		return res;

	return add_sentinel(args);
}

int f_sys_send_e_common(struct event_filler_arguments *args, int *fd)
{
	int res;
	unsigned long size;
	unsigned long val;

	/*
	 * fd
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	else
		val = args->socketcall_args[0];

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	*fd = val;

	/*
	 * size
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 2, 1, &size);
	else
		size = args->socketcall_args[2];

	res = val_to_ring(args, size, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return PPM_SUCCESS;
}

int f_sys_send_e(struct event_filler_arguments *args)
{
	int res;
	int fd;

	res = f_sys_send_e_common(args, &fd);

	if (likely(res == PPM_SUCCESS))
		return add_sentinel(args);
	return res;
}

int f_sys_sendto_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	u16 size = 0;
	char *targetbuf = args->str_storage;
	int fd;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;
	int err = 0;

	*targetbuf = 250;

	/*
	 * Push the common params to the ring
	 */
	res = f_sys_send_e_common(args, &fd);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Get the address
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 4, 1, &val);
	else
		val = args->socketcall_args[4];

	usrsockaddr = (struct sockaddr __user *)val;

	/*
	 * Get the address len
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 5, 1, &val);
	else
		val = args->socketcall_args[5];

	if (usrsockaddr != NULL && val != 0) {
		/*
		 * Copy the address
		 */
		err = addr_to_kernel(usrsockaddr, val, (struct sockaddr *)&address);
		if (likely(err >= 0)) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = fd_to_socktuple(fd,
				(struct sockaddr *)&address,
				val,
				true,
				false,
				targetbuf,
				STR_STORAGE_SIZE);
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_send_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long bufsize;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	else
		val = args->socketcall_args[0];

	args->fd = (int)val;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * data
	 */
	if (retval < 0) {
		/*
		 * The operation failed, return an empty buffer
		 */
		val = 0;
		bufsize = 0;
	} else {
		if (!args->is_socketcall)
			syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
		else
			val = args->socketcall_args[1];

		/*
		 * The return value can be lower than the value provided by the user,
		 * and we take that into account.
		 */
		bufsize = retval;
	}

	args->enforce_snaplen = true;
	res = val_to_ring(args, val, bufsize, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_recv_x_common(struct event_filler_arguments *args, int64_t *retval)
{
	int res;
	unsigned long val;
	unsigned long bufsize;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	else
		val = args->socketcall_args[1];

	args->fd = (int)val;

	/*
	 * res
	 */
	*retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, *retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * data
	 */
	if (*retval < 0) {
		/*
		 * The operation failed, return an empty buffer
		 */
		val = 0;
		bufsize = 0;
	} else {
		if (!args->is_socketcall)
			syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
		else
			val = args->socketcall_args[1];

		/*
		 * The return value can be lower than the value provided by the user,
		 * and we take that into account.
		 */
		bufsize = *retval;
	}

	args->enforce_snaplen = true;
	res = val_to_ring(args, val, bufsize, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return PPM_SUCCESS;
}

int f_sys_recv_x(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;

	res = f_sys_recv_x_common(args, &retval);

	if (likely(res == PPM_SUCCESS))
		return add_sentinel(args);
	return res;
}

int f_sys_recvfrom_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	u16 size = 0;
	int64_t retval;
	char *targetbuf = args->str_storage;
	int fd;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;
	int addrlen;
	int err = 0;

	/*
	 * Push the common params to the ring
	 */
	res = f_sys_recv_x_common(args, &retval);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	if (retval >= 0) {
		/*
		 * Get the fd
		 */
		if (!args->is_socketcall) {
			syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
			fd = (int)val;
		} else
			fd = (int)args->socketcall_args[0];

		/*
		 * Get the address
		 */
		if (!args->is_socketcall)
			syscall_get_arguments_deprecated(current, args->regs, 4, 1, &val);
		else
			val = args->socketcall_args[4];
		usrsockaddr = (struct sockaddr __user *)val;

		/*
		 * Get the address len
		 */
		if (!args->is_socketcall)
			syscall_get_arguments_deprecated(current, args->regs, 5, 1, &val);
		else
			val = args->socketcall_args[5];
		if (usrsockaddr != NULL && val != 0) {
#ifdef CONFIG_COMPAT
			if (!args->compat) {
#endif
				if (unlikely(ppm_copy_from_user(&addrlen, (const void __user *)val, sizeof(addrlen))))
					return PPM_FAILURE_INVALID_USER_MEMORY;
#ifdef CONFIG_COMPAT
			} else {
				if (unlikely(ppm_copy_from_user(&addrlen, (const void __user *)compat_ptr(val), sizeof(addrlen))))
					return PPM_FAILURE_INVALID_USER_MEMORY;
			}
#endif

			/*
			 * Copy the address
			 */
			err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
			if (likely(err >= 0)) {
				/*
				 * Convert the fd into socket endpoint information
				 */
				size = fd_to_socktuple(fd,
					(struct sockaddr *)&address,
					addrlen,
					true,
					true,
					targetbuf,
					STR_STORAGE_SIZE);
			}
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_sendmsg_e(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	struct user_msghdr mh;
#else
	struct msghdr mh;
#endif
	char *targetbuf = args->str_storage;
	const struct iovec __user *iov;
#ifdef CONFIG_COMPAT
	const struct compat_iovec __user *compat_iov;
	struct compat_msghdr compat_mh;
#endif
	unsigned long iovcnt;
	int fd;
	u16 size = 0;
	int addrlen;
	int err = 0;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;

	/*
	 * fd
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	else
		val = args->socketcall_args[0];

	fd = val;
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Retrieve the message header
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	else
		val = args->socketcall_args[1];

#ifdef CONFIG_COMPAT
	if (!args->compat) {
#endif
		if (unlikely(ppm_copy_from_user(&mh, (const void __user *)val, sizeof(mh))))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		/*
		 * size
		 */
		iov = (const struct iovec __user *)mh.msg_iov;
		iovcnt = mh.msg_iovlen;

		res = parse_readv_writev_bufs(args, iov, iovcnt, args->consumer->snaplen, PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);


		if (unlikely(res != PPM_SUCCESS))
			return res;

		/*
		 * tuple
		 */
		usrsockaddr = (struct sockaddr __user *)mh.msg_name;
		addrlen = mh.msg_namelen;
#ifdef CONFIG_COMPAT
	} else {
		if (unlikely(ppm_copy_from_user(&compat_mh, (const void __user *)compat_ptr(val), sizeof(compat_mh))))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		/*
		 * size
		 */
		compat_iov = (const struct compat_iovec __user *)compat_ptr(compat_mh.msg_iov);
		iovcnt = compat_mh.msg_iovlen;

		res = compat_parse_readv_writev_bufs(args, compat_iov, iovcnt, args->consumer->snaplen, PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);


		if (unlikely(res != PPM_SUCCESS))
			return res;

		/*
		 * tuple
		 */
		usrsockaddr = (struct sockaddr __user *)compat_ptr(compat_mh.msg_name);
		addrlen = compat_mh.msg_namelen;
	}
#endif

	if (usrsockaddr != NULL && addrlen != 0) {
		/*
		 * Copy the address
		 */
		err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
		if (likely(err >= 0)) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = fd_to_socktuple(fd,
				(struct sockaddr *)&address,
				addrlen,
				true,
				false,
				targetbuf,
				STR_STORAGE_SIZE);
		}
	}

	/* Copy the endpoint info into the ring */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_sendmsg_x(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;
	int64_t retval;
	const struct iovec __user *iov;
#ifdef CONFIG_COMPAT
	const struct compat_iovec __user *compat_iov;
	struct compat_msghdr compat_mh;
#endif
	unsigned long iovcnt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	struct user_msghdr mh;
#else
	struct msghdr mh;
#endif

	/*
	 * res
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Retrieve the message header
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	else
		val = args->socketcall_args[1];

	/*
	 * data
	 */
#ifdef CONFIG_COMPAT
	if (!args->compat) {
#endif
		if (unlikely(ppm_copy_from_user(&mh, (const void __user *)val, sizeof(mh))))
			return PPM_FAILURE_INVALID_USER_MEMORY;


		iov = (const struct iovec __user *)mh.msg_iov;
		iovcnt = mh.msg_iovlen;

		res = parse_readv_writev_bufs(args, iov, iovcnt, args->consumer->snaplen, PRB_FLAG_PUSH_DATA | PRB_FLAG_IS_WRITE);
		if (unlikely(res != PPM_SUCCESS))
			return res;
#ifdef CONFIG_COMPAT
	} else {
		if (unlikely(ppm_copy_from_user(&compat_mh, (const void __user *)compat_ptr(val), sizeof(compat_mh))))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		compat_iov = (const struct compat_iovec __user *)compat_ptr(compat_mh.msg_iov);
		iovcnt = compat_mh.msg_iovlen;

		res = compat_parse_readv_writev_bufs(args, compat_iov, iovcnt, args->consumer->snaplen, PRB_FLAG_PUSH_DATA | PRB_FLAG_IS_WRITE);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}
#endif

	return add_sentinel(args);
}

int f_sys_recvmsg_x(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;
	int64_t retval;
	const struct iovec __user *iov;
#ifdef CONFIG_COMPAT
	const struct compat_iovec __user *compat_iov;
	struct compat_msghdr compat_mh;
#endif
	unsigned long iovcnt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	struct user_msghdr mh;
#else
	struct msghdr mh;
#endif
	char *targetbuf = args->str_storage;
	int fd;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;
	u16 size = 0;
	int addrlen;
	int err = 0;

	/*
	 * res
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Retrieve the message header
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	else
		val = args->socketcall_args[1];


#ifdef CONFIG_COMPAT
	if (!args->compat) {
#endif
		if (unlikely(ppm_copy_from_user(&mh, (const void __user *)val, sizeof(mh))))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		/*
		 * data and size
		 */
		iov = (const struct iovec __user *)mh.msg_iov;
		iovcnt = mh.msg_iovlen;

		res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
#ifdef CONFIG_COMPAT
	} else {
		if (unlikely(ppm_copy_from_user(&compat_mh, (const void __user *)compat_ptr(val), sizeof(compat_mh))))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		/*
		 * data and size
		 */
		compat_iov = (const struct compat_iovec __user *)compat_ptr(compat_mh.msg_iov);
		iovcnt = compat_mh.msg_iovlen;

		res = compat_parse_readv_writev_bufs(args, compat_iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
	}
#endif

	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * tuple
	 */
	if (retval >= 0) {
		/*
		 * Get the fd
		 */
		if (!args->is_socketcall) {
			syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
			fd = (int)val;
		} else
			fd = (int)args->socketcall_args[0];

		/*
		 * Get the address
		 */
		usrsockaddr = (struct sockaddr __user *)mh.msg_name;
		addrlen = mh.msg_namelen;

		if (usrsockaddr != NULL && addrlen != 0) {
			/*
			 * Copy the address
			 */
			err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
			if (likely(err >= 0)) {
				/*
				 * Convert the fd into socket endpoint information
				 */
				size = fd_to_socktuple(fd,
					(struct sockaddr *)&address,
					addrlen,
					true,
					true,
					targetbuf,
					STR_STORAGE_SIZE);
			}
		}
	}

	/* Copy the endpoint info into the ring */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_creat_x(struct event_filler_arguments *args)
{
	unsigned long val;
	unsigned long modes;
	int res;
	int64_t retval;

	/*
	 * fd
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 *  mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &modes);
	res = val_to_ring(args, open_modes_to_scap(O_CREAT, modes), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * dev
	 */
	res = val_to_ring(args, get_fd_dev(retval), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_pipe_x(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	unsigned long val;
	int fds[2];
	struct file *file;

	/*
	 * retval
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * fds
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

#ifdef CONFIG_COMPAT
	if (!args->compat) {
#endif
		if (unlikely(ppm_copy_from_user(fds, (const void __user *)val, sizeof(fds))))
			return PPM_FAILURE_INVALID_USER_MEMORY;
#ifdef CONFIG_COMPAT
	} else {
		if (unlikely(ppm_copy_from_user(fds, (const void __user *)compat_ptr(val), sizeof(fds))))
			return PPM_FAILURE_INVALID_USER_MEMORY;
	}
#endif

	res = val_to_ring(args, fds[0], 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	res = val_to_ring(args, fds[1], 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	file = fget(fds[0]);
	val = 0;
	if (likely(file != NULL)) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		val = file->f_path.dentry->d_inode->i_ino;
#else
		val = file->f_dentry->d_inode->i_ino;
#endif
		fput(file);
	}

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_eventfd_e(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;

	/*
	 * initval
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * flags
	 * XXX not implemented yet
	 */
	/* syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val); */
	val = 0;
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_shutdown_e(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;

	/*
	 * fd
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	else
		val = args->socketcall_args[0];

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * how
	 */
	if (!args->is_socketcall)
		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	else
		val = args->socketcall_args[1];

	res = val_to_ring(args, (unsigned long)shutdown_how_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_futex_e(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;

	/*
	 * addr
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * op
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, (unsigned long)futex_op_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * val
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_lseek_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * offset
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * whence
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, lseek_whence_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_llseek_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	unsigned long oh;
	unsigned long ol;
	uint64_t offset;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * offset
	 * We build it by combining the offset_high and offset_low system call arguments
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &oh);
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &ol);
	offset = (((uint64_t)oh) << 32) + ((uint64_t)ol);
	res = val_to_ring(args, offset, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * whence
	 */
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &val);
	res = val_to_ring(args, lseek_whence_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int poll_parse_fds(struct event_filler_arguments *args, bool enter_event)
{
	struct pollfd *fds;
	char *targetbuf;
	unsigned long val;
	unsigned long nfds;
	unsigned long fds_count;
	u32 j;
	u32 pos;
	u16 flags;

	/*
	 * fds
	 *
	 * Get the number of fds
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &nfds);

	/*
	 * Check if we have enough space to store both the fd list
	 * from user space and the temporary buffer to serialize to the ring
	 */
	if (unlikely(sizeof(struct pollfd) * nfds + 2 + 10 * nfds > STR_STORAGE_SIZE))
		return PPM_FAILURE_BUFFER_FULL;

	/* Get the fds pointer */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	fds = (struct pollfd *)args->str_storage;
#ifdef CONFIG_COMPAT
	if (!args->compat) {
#endif
		if (unlikely(ppm_copy_from_user(fds, (const void __user *)val, nfds * sizeof(struct pollfd))))
			return PPM_FAILURE_INVALID_USER_MEMORY;
#ifdef CONFIG_COMPAT
	} else {
		if (unlikely(ppm_copy_from_user(fds, (const void __user *)compat_ptr(val), nfds * sizeof(struct pollfd))))
			return PPM_FAILURE_INVALID_USER_MEMORY;
	}
#endif

	pos = 2;
	targetbuf = args->str_storage + nfds * sizeof(struct pollfd) + pos;
	fds_count = 0;

	/* Copy each fd into the temporary buffer */
	for (j = 0; j < nfds; j++) {
		if (enter_event) {
			flags = poll_events_to_scap(fds[j].events);
		} else {
			/*
			 * If it's an exit event, we copy only the fds that
			 * returned something
			 */
			if (!fds[j].revents)
				continue;

			flags = poll_events_to_scap(fds[j].revents);
		}

		*(int64_t *)(targetbuf + pos) = fds[j].fd;
		*(int16_t *)(targetbuf + pos + 8) = flags;
		pos += 10;
		++fds_count;
	}

	*(u16 *)(targetbuf) = (u16)fds_count;

	return val_to_ring(args, (uint64_t)(unsigned long)targetbuf, pos, false, 0);
}

int f_sys_poll_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	res = poll_parse_fds(args, true);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * timeout
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int timespec_parse(struct event_filler_arguments *args, unsigned long val)
{
	uint64_t longtime;
	char *targetbuf = args->str_storage;
	struct timespec *tts = (struct timespec *)targetbuf;
#ifdef CONFIG_COMPAT
	struct compat_timespec *compat_tts = (struct compat_timespec *)targetbuf;
#endif
	int cfulen;

	/*
	 * interval
	 * We copy the timespec structure and then convert it to a 64bit relative time
	 */
#ifdef CONFIG_COMPAT
	if (!args->compat) {
#endif
		cfulen = (int)ppm_copy_from_user(targetbuf, (void __user *)val, sizeof(*tts));
		if (unlikely(cfulen != 0))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		longtime = ((uint64_t)tts->tv_sec) * 1000000000 + tts->tv_nsec;
#ifdef CONFIG_COMPAT
	} else {
		cfulen = (int)ppm_copy_from_user(targetbuf, (void __user *)compat_ptr(val), sizeof(struct compat_timespec));
		if (unlikely(cfulen != 0))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		longtime = ((uint64_t)compat_tts->tv_sec) * 1000000000 + compat_tts->tv_nsec;
	}
#endif

	return val_to_ring(args, longtime, 0, false, 0);
}

int f_sys_ppoll_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	res = poll_parse_fds(args, true);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * timeout
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	/* NULL timeout specified as 0xFFFFFF.... */
	if (val == (unsigned long)NULL)
		res = val_to_ring(args, (uint64_t)(-1), 0, false, 0);
	else
		res = timespec_parse(args, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * sigmask
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	if (val != (unsigned long)NULL)
		if (0 != ppm_copy_from_user(&val, (void __user *)val, sizeof(val)))
			return PPM_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, val, 0, false, 0);
	if (res != PPM_SUCCESS)
		return res;

	return add_sentinel(args);
}

/* This is the same for poll() and ppoll() */
int f_sys_poll_x(struct event_filler_arguments *args)
{
	int64_t retval;
	int res;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	res = poll_parse_fds(args, false);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_mount_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * Fix mount flags in arg 3.
	 * See http://lxr.free-electrons.com/source/fs/namespace.c?v=4.2#L2650
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	if ((val & PPM_MS_MGC_MSK) == PPM_MS_MGC_VAL)
		val &= ~PPM_MS_MGC_MSK;
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_openat_x(struct event_filler_arguments *args)
{
	unsigned long val;
	unsigned long flags;
	unsigned long modes;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Flags
	 * Note that we convert them into the ppm portable representation before pushing them to the ring
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &flags);
	res = val_to_ring(args, open_flags_to_scap(flags), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 *  mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &modes);
	res = val_to_ring(args, open_modes_to_scap(flags, modes), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * dev
	 */
	res = val_to_ring(args, get_fd_dev(retval), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_unlinkat_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * flags
	 * Note that we convert them into the ppm portable representation before pushing them to the ring
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, unlinkat_flags_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_linkat_x(struct event_filler_arguments *args)
{
	unsigned long val;
	unsigned long flags;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * olddir
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * oldpath
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * newdir
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);

	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * newpath
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Flags
	 * Note that we convert them into the ppm portable representation before pushing them to the ring
	 */
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &flags);
	res = val_to_ring(args, linkat_flags_to_scap(flags), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

#ifndef _64BIT_ARGS_SINGLE_REGISTER
int f_sys_pread64_e(struct event_filler_arguments *args)
{
	unsigned long val;
	unsigned long size;
	int res;
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &size);
	res = val_to_ring(args, size, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pos
	 */
#if defined CONFIG_X86
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &pos1);
#elif defined CONFIG_ARM && CONFIG_AEABI
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &pos0);
	syscall_get_arguments_deprecated(current, args->regs, 5, 1, &pos1);
#else
 #error This architecture/abi not yet supported
#endif

	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}
#endif /* _64BIT_ARGS_SINGLE_REGISTER */

#ifndef _64BIT_ARGS_SINGLE_REGISTER
int f_sys_pwrite64_e(struct event_filler_arguments *args)
{
	unsigned long val;
	unsigned long size;
	int res;
#ifndef _64BIT_ARGS_SINGLE_REGISTER
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;
#endif

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &size);
	res = val_to_ring(args, size, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pos
	 * NOTE: this is a 64bit value, which means that on 32bit systems it uses two
	 * separate registers that we need to merge.
	 */
#ifdef _64BIT_ARGS_SINGLE_REGISTER
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;
#else
 #if defined CONFIG_X86
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &pos1);
 #elif defined CONFIG_ARM && CONFIG_AEABI
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &pos0);
	syscall_get_arguments_deprecated(current, args->regs, 5, 1, &pos1);
 #else
  #error This architecture/abi not yet supported
 #endif

	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;
#endif

	return add_sentinel(args);
}
#endif

int f_sys_readv_preadv_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int64_t retval;
	int res;
#ifdef CONFIG_COMPAT
	const struct compat_iovec __user *compat_iov;
#endif
	const struct iovec __user *iov;
	unsigned long iovcnt;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * data and size
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &iovcnt);

#ifdef CONFIG_COMPAT
	if (unlikely(args->compat)) {
		compat_iov = (const struct compat_iovec __user *)compat_ptr(val);
		res = compat_parse_readv_writev_bufs(args, compat_iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
	} else
#endif
	{
		iov = (const struct iovec __user *)val;
		res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
	}
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_writev_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
#ifdef CONFIG_COMPAT
	const struct compat_iovec __user *compat_iov;
#endif
	const struct iovec __user *iov;
	unsigned long iovcnt;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &iovcnt);

	/*
	 * Copy the buffer
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
#ifdef CONFIG_COMPAT
	if (unlikely(args->compat)) {
		compat_iov = (const struct compat_iovec __user *)compat_ptr(val);
		res = compat_parse_readv_writev_bufs(args, compat_iov, iovcnt,
											args->consumer->snaplen,
											PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	} else
#endif
	{
		iov = (const struct iovec __user *)val;
		res = parse_readv_writev_bufs(args, iov, iovcnt, args->consumer->snaplen,
									  PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	}

	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_writev_pwritev_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
#ifdef CONFIG_COMPAT
	const struct compat_iovec __user *compat_iov;
#endif
	const struct iovec __user *iov;
	unsigned long iovcnt;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * data and size
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &iovcnt);


	/*
	 * Copy the buffer
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
#ifdef CONFIG_COMPAT
	if (unlikely(args->compat)) {
		compat_iov = (const struct compat_iovec __user *)compat_ptr(val);
		res = compat_parse_readv_writev_bufs(args, compat_iov, iovcnt, args->consumer->snaplen, PRB_FLAG_PUSH_DATA | PRB_FLAG_IS_WRITE);
	} else
#endif
	{
		iov = (const struct iovec __user *)val;
		res = parse_readv_writev_bufs(args, iov, iovcnt, args->consumer->snaplen, PRB_FLAG_PUSH_DATA | PRB_FLAG_IS_WRITE);
	}
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

#ifndef _64BIT_ARGS_SINGLE_REGISTER
int f_sys_preadv64_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pos
	 */

	/*
	 * Note that in preadv and pwritev have NO 64-bit arguments in the
	 * syscall (despite having one in the userspace API), so no alignment
	 * requirements apply here. For an overly-detailed discussion about
	 * this, see https://lwn.net/Articles/311630/
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &pos1);

	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}
#endif /* _64BIT_ARGS_SINGLE_REGISTER */

int f_sys_pwritev_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
#ifndef _64BIT_ARGS_SINGLE_REGISTER
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;
#endif
#ifdef CONFIG_COMPAT
	const struct compat_iovec __user *compat_iov;
#endif
	const struct iovec __user *iov;
	unsigned long iovcnt;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &iovcnt);

	/*
	 * Copy the buffer
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
#ifdef CONFIG_COMPAT
	if (unlikely(args->compat)) {
		compat_iov = (const struct compat_iovec __user *)compat_ptr(val);
		res = compat_parse_readv_writev_bufs(args, compat_iov, iovcnt,
									args->consumer->snaplen,
									PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	} else
#endif
	{
		iov = (const struct iovec __user *)val;
		res = parse_readv_writev_bufs(args, iov, iovcnt, args->consumer->snaplen,
									  PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	}
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pos
	 * NOTE: this is a 64bit value, which means that on 32bit systems it uses two
	 * separate registers that we need to merge.
	 */
#ifdef _64BIT_ARGS_SINGLE_REGISTER
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;
#else
	/*
	 * Note that in preadv and pwritev have NO 64-bit arguments in the
	 * syscall (despite having one in the userspace API), so no alignment
	 * requirements apply here. For an overly-detailed discussion about
	 * this, see https://lwn.net/Articles/311630/
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &pos1);

	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;
#endif

	return add_sentinel(args);
}

int f_sys_nanosleep_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = timespec_parse(args, val);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_getrlimit_setrlimit_e(struct event_filler_arguments *args)
{
	u8 ppm_resource;
	unsigned long val;
	int res;

	/*
	 * resource
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	ppm_resource = rlimit_resource_to_scap(val);

	res = val_to_ring(args, (uint64_t)ppm_resource, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_getrlimit_setrlrimit_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	struct rlimit rl;
#ifdef CONFIG_COMPAT
	struct compat_rlimit compat_rl;
#endif
	int64_t cur;
	int64_t max;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Copy the user structure and extract cur and max
	 */
	if (retval >= 0 || args->event_type == PPME_SYSCALL_SETRLIMIT_X) {
		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);

#ifdef CONFIG_COMPAT
		if (!args->compat) {
#endif
			if (unlikely(ppm_copy_from_user(&rl, (const void __user *)val, sizeof(struct rlimit))))
				return PPM_FAILURE_INVALID_USER_MEMORY;
			cur = rl.rlim_cur;
			max = rl.rlim_max;
#ifdef CONFIG_COMPAT
		} else {
			if (unlikely(ppm_copy_from_user(&compat_rl, (const void __user *)compat_ptr(val), sizeof(struct compat_rlimit))))
				return PPM_FAILURE_INVALID_USER_MEMORY;
			cur = compat_rl.rlim_cur;
			max = compat_rl.rlim_max;
		}
#endif
	} else {
		cur = -1;
		max = -1;
	}

	/*
	 * cur
	 */
	res = val_to_ring(args, cur, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * max
	 */
	res = val_to_ring(args, max, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_prlimit_e(struct event_filler_arguments *args)
{
	u8 ppm_resource;
	unsigned long val;
	int res;

	/*
	 * pid
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * resource
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);

	ppm_resource = rlimit_resource_to_scap(val);

	res = val_to_ring(args, (uint64_t)ppm_resource, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_prlimit_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	struct rlimit rl;
#ifdef CONFIG_COMPAT
	struct compat_rlimit compat_rl;
#endif
	int64_t newcur;
	int64_t newmax;
	int64_t oldcur;
	int64_t oldmax;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Copy the user structure and extract cur and max
	 */
	if (retval >= 0) {
		syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);

#ifdef CONFIG_COMPAT
		if (!args->compat) {
#endif
			if (unlikely(ppm_copy_from_user(&rl, (const void __user *)val, sizeof(struct rlimit)))) {
				newcur = -1;
				newmax = -1;
			} else {
				newcur = rl.rlim_cur;
				newmax = rl.rlim_max;
			}
#ifdef CONFIG_COMPAT
		} else {
			if (unlikely(ppm_copy_from_user(&compat_rl, (const void __user *)val, sizeof(struct compat_rlimit)))) {
				newcur = -1;
				newmax = -1;
			} else {
				newcur = compat_rl.rlim_cur;
				newmax = compat_rl.rlim_max;
			}
		}
#endif
	} else {
		newcur = -1;
		newmax = -1;
	}

	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);

#ifdef CONFIG_COMPAT
	if (!args->compat) {
#endif
		if (unlikely(ppm_copy_from_user(&rl, (const void __user *)val, sizeof(struct rlimit)))) {
			oldcur = -1;
			oldmax = -1;
		} else {
			oldcur = rl.rlim_cur;
			oldmax = rl.rlim_max;
		}
#ifdef CONFIG_COMPAT
	} else {
		if (unlikely(ppm_copy_from_user(&compat_rl, (const void __user *)val, sizeof(struct compat_rlimit)))) {
			oldcur = -1;
			oldmax = -1;
		} else {
			oldcur = compat_rl.rlim_cur;
			oldmax = compat_rl.rlim_max;
		}
	}
#endif

	/*
	 * newcur
	 */
	res = val_to_ring(args, newcur, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * newmax
	 */
	res = val_to_ring(args, newmax, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * oldcur
	 */
	res = val_to_ring(args, oldcur, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * oldmax
	 */
	res = val_to_ring(args, oldmax, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

#ifdef CAPTURE_CONTEXT_SWITCHES

int f_sched_switch_e(struct event_filler_arguments *args)
{
	int res;
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;
	struct mm_struct *mm = NULL;

	if (args->sched_prev == NULL || args->sched_next == NULL) {
		ASSERT(false);
		return -1;
	}

	/*
	 * next
	 */
	res = val_to_ring(args, args->sched_next->pid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pgft_maj
	 */
	res = val_to_ring(args, args->sched_prev->maj_flt, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pgft_min
	 */
	res = val_to_ring(args, args->sched_prev->min_flt, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	mm = args->sched_prev->mm;
	if (mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT-10);
		total_rss = ppm_get_mm_rss(mm) << (PAGE_SHIFT-10);
		swap = ppm_get_mm_swap(mm) << (PAGE_SHIFT-10);
	}

	/*
	 * vm_size
	 */
	res = val_to_ring(args, total_vm, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * vm_rss
	 */
	res = val_to_ring(args, total_rss, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * vm_swap
	 */
	res = val_to_ring(args, swap, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

#if 0
	/*
	 * steal
	 */
	steal = cputime64_to_clock_t(kcpustat_this_cpu->cpustat[CPUTIME_STEAL]);
	res = val_to_ring(args, steal, 0, false);
	if (unlikely(res != PPM_SUCCESS))
		return res;
#endif

	return add_sentinel(args);
}
#endif /* CAPTURE_CONTEXT_SWITCHES */

int f_sched_drop(struct event_filler_arguments *args)
{
	int res;

	/*
	 * ratio
	 */
	res = val_to_ring(args, args->consumer->sampling_ratio, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_fcntl_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * cmd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, fcntl_cmd_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static inline int parse_ptrace_addr(struct event_filler_arguments *args, u16 request)
{
	unsigned long val;
	uint64_t dst;
	u8 idx;

	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	switch (request) {
	default:
		idx = PPM_PTRACE_IDX_UINT64;
		dst = (uint64_t)val;
	}

	return val_to_ring(args, dst, 0, false, idx);
}

static inline int parse_ptrace_data(struct event_filler_arguments *args, u16 request)
{
	unsigned long val;
	unsigned long len;
	uint64_t dst;
	u8 idx;

	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	switch (request) {
	case PPM_PTRACE_PEEKTEXT:
	case PPM_PTRACE_PEEKDATA:
	case PPM_PTRACE_PEEKUSR:
		idx = PPM_PTRACE_IDX_UINT64;
#ifdef CONFIG_COMPAT
		if (!args->compat) {
#endif
			len = ppm_copy_from_user(&dst, (const void __user *)val, sizeof(long));
#ifdef CONFIG_COMPAT
		} else {
			len = ppm_copy_from_user(&dst, (const void __user *)compat_ptr(val), sizeof(compat_long_t));
		}
#endif
		if (unlikely(len != 0))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		break;
	case PPM_PTRACE_CONT:
	case PPM_PTRACE_SINGLESTEP:
	case PPM_PTRACE_DETACH:
	case PPM_PTRACE_SYSCALL:
		idx = PPM_PTRACE_IDX_SIGTYPE;
		dst = (uint64_t)val;
		break;
	case PPM_PTRACE_ATTACH:
	case PPM_PTRACE_TRACEME:
	case PPM_PTRACE_POKETEXT:
	case PPM_PTRACE_POKEDATA:
	case PPM_PTRACE_POKEUSR:
	default:
		idx = PPM_PTRACE_IDX_UINT64;
		dst = (uint64_t)val;
		break;
	}

	return val_to_ring(args, dst, 0, false, idx);
}

int f_sys_ptrace_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * request
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, ptrace_requests_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pid
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_ptrace_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int64_t retval;
	u16 request;
	int res;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	if (retval < 0) {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		return add_sentinel(args);
	}

	/*
	 * request
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	request = ptrace_requests_to_scap(val);

	res = parse_ptrace_addr(args, request);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	res = parse_ptrace_data(args, request);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_brk_munmap_mmap_x(struct event_filler_arguments *args)
{
	int64_t retval;
	int res = 0;
	struct mm_struct *mm = current->mm;
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;

	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	if (mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT-10);
		total_rss = ppm_get_mm_rss(mm) << (PAGE_SHIFT-10);
		swap = ppm_get_mm_swap(mm) << (PAGE_SHIFT-10);
	}

	/*
	 * vm_size
	 */
	res = val_to_ring(args, total_vm, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * vm_rss
	 */
	res = val_to_ring(args, total_rss, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * vm_swap
	 */
	res = val_to_ring(args, swap, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_mmap_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * addr
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * length
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * prot
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, prot_flags_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * flags
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, mmap_flags_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 4, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * offset/pgoffset
	 */
	syscall_get_arguments_deprecated(current, args->regs, 5, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_renameat_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * olddirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * oldpath
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * newdirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);

	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * newpath
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_symlinkat_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * oldpath
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * newdirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);

	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * newpath
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_procexit_e(struct event_filler_arguments *args)
{
	int res;

	if (args->sched_prev == NULL) {
		ASSERT(false);
		return -1;
	}

	/*
	 * status
	 */
	res = val_to_ring(args, args->sched_prev->exit_code, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_sendfile_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	off_t offset;

	/*
	 * out_fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * in_fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * offset
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);

	if (val != 0) {
#ifdef CONFIG_COMPAT
		if (!args->compat) {
#endif
			res = ppm_copy_from_user(&offset, (void *)val, sizeof(off_t));
#ifdef CONFIG_COMPAT
		} else {
			res = ppm_copy_from_user(&offset, (void *)compat_ptr(val), sizeof(compat_off_t));
		}
#endif
		if (unlikely(res))
			val = 0;
		else
			val = offset;
	}

	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_sendfile_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	off_t offset;

	/*
	 * res
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * offset
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);

	if (val != 0) {
#ifdef CONFIG_COMPAT
		if (!args->compat) {
#endif
			res = ppm_copy_from_user(&offset, (void *)val, sizeof(off_t));
#ifdef CONFIG_COMPAT
		} else {
			res = ppm_copy_from_user(&offset, (void *)compat_ptr(val), sizeof(compat_off_t));
		}
#endif
		if (unlikely(res))
			val = 0;
		else
			val = offset;
	}

	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_quotactl_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	uint32_t id;
	uint8_t quota_fmt;
	uint16_t cmd;

	/*
	 * extract cmd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	cmd = quotactl_cmd_to_scap(val);
	res = val_to_ring(args, cmd, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * extract type
	 */
	res = val_to_ring(args, quotactl_type_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 *  extract id
	 */
	id = 0;
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	if ((cmd == PPM_Q_GETQUOTA) ||
		 (cmd == PPM_Q_SETQUOTA) ||
		 (cmd == PPM_Q_XGETQUOTA) ||
		 (cmd == PPM_Q_XSETQLIM)) {
		/*
		 * in this case id represent an userid or groupid so add it
		 */
		id = val;
	}
	res = val_to_ring(args, id, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * extract quota_fmt from id
	 */
	quota_fmt = PPM_QFMT_NOT_USED;
	if (cmd == PPM_Q_QUOTAON)
		quota_fmt = quotactl_fmt_to_scap(val);

	res = val_to_ring(args, quota_fmt, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_quotactl_x(struct event_filler_arguments *args)
{
	unsigned long val, len;
	int res;
	int64_t retval;
	uint16_t cmd;
	struct if_dqblk dqblk;
	struct if_dqinfo dqinfo;
	uint32_t quota_fmt_out;

	const char empty_string[] = "";

	/*
	 * extract cmd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	cmd = quotactl_cmd_to_scap(val);

	/*
	 * return value
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Add special
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * get addr
	 */
	syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);

	/*
	 * get quotafilepath only for QUOTAON
	 */
	if (cmd == PPM_Q_QUOTAON)
		res = val_to_ring(args, val, 0, true, 0);
	else
		res = val_to_ring(args, (unsigned long)empty_string, 0, false, 0);

	if (unlikely(res != PPM_SUCCESS))
		return res;


	/*
	 * dqblk fields if present
	 */
	dqblk.dqb_valid = 0;
	if ((cmd == PPM_Q_GETQUOTA) || (cmd == PPM_Q_SETQUOTA)) {
		len = ppm_copy_from_user(&dqblk, (void *)val, sizeof(struct if_dqblk));
		if (unlikely(len != 0))
			return PPM_FAILURE_INVALID_USER_MEMORY;
	}
	if (dqblk.dqb_valid & QIF_BLIMITS) {
		res = val_to_ring(args, dqblk.dqb_bhardlimit, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
		res = val_to_ring(args, dqblk.dqb_bsoftlimit, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	if (dqblk.dqb_valid & QIF_SPACE) {
		res = val_to_ring(args, dqblk.dqb_curspace, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	if (dqblk.dqb_valid & QIF_ILIMITS) {
		res = val_to_ring(args, dqblk.dqb_ihardlimit, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
		res = val_to_ring(args, dqblk.dqb_isoftlimit, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	if (dqblk.dqb_valid & QIF_BTIME) {
		res = val_to_ring(args, dqblk.dqb_btime, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	if (dqblk.dqb_valid & QIF_ITIME) {
		res = val_to_ring(args, dqblk.dqb_itime, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	/*
	 * dqinfo fields if present
	 */
	dqinfo.dqi_valid = 0;
	if ((cmd == PPM_Q_GETINFO) || (cmd == PPM_Q_SETINFO)) {
		len = ppm_copy_from_user(&dqinfo, (void *)val, sizeof(struct if_dqinfo));
		if (unlikely(len != 0))
			return PPM_FAILURE_INVALID_USER_MEMORY;
	}

	if (dqinfo.dqi_valid & IIF_BGRACE) {
		res = val_to_ring(args, dqinfo.dqi_bgrace, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	if (dqinfo.dqi_valid & IIF_IGRACE) {
		res = val_to_ring(args, dqinfo.dqi_igrace, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	if (dqinfo.dqi_valid & IIF_FLAGS) {
		res = val_to_ring(args, dqinfo.dqi_flags, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	quota_fmt_out = PPM_QFMT_NOT_USED;
	if (cmd == PPM_Q_GETFMT) {
		len = ppm_copy_from_user(&quota_fmt_out, (void *)val, sizeof(uint32_t));
		if (unlikely(len != 0))
			return PPM_FAILURE_INVALID_USER_MEMORY;
		quota_fmt_out = quotactl_fmt_to_scap(quota_fmt_out);
	}
	res = val_to_ring(args, quota_fmt_out, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_sysdigevent_e(struct event_filler_arguments *args)
{
	int res;

	/*
	 * event_type
	 */
	res = val_to_ring(args, (unsigned long)args->sched_prev, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * event_data
	 */
	res = val_to_ring(args, (unsigned long)args->sched_next, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_getresuid_and_gid_x(struct event_filler_arguments *args)
{
	int res;
	unsigned long val, len;
	uint32_t uid;
	int16_t retval;

	/*
	 * return value
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * ruid
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
#ifdef CONFIG_COMPAT
	if (!args->compat) {
#endif
		len = ppm_copy_from_user(&uid, (void *)val, sizeof(uint32_t));
#ifdef CONFIG_COMPAT
	} else {
		len = ppm_copy_from_user(&uid, (void *)compat_ptr(val), sizeof(uint32_t));
	}
#endif
	if (unlikely(len != 0))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, uid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * euid
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	len = ppm_copy_from_user(&uid, (void *)val, sizeof(uint32_t));
	if (unlikely(len != 0))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, uid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * suid
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	len = ppm_copy_from_user(&uid, (void *)val, sizeof(uint32_t));
	if (unlikely(len != 0))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, uid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_flock_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	u32 flags;

	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	flags = flock_flags_to_scap(val);
	res = val_to_ring(args, flags, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_setns_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	u32 flags;

	/*
	 * parse fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * get type, parse as clone flags as it's a subset of it
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	flags = clone_flags_to_scap(val);
	res = val_to_ring(args, flags, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_unshare_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	u32 flags;

	/*
	 * get type, parse as clone flags as it's a subset of it
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	flags = clone_flags_to_scap(val);
	res = val_to_ring(args, flags, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

#ifdef CAPTURE_SIGNAL_DELIVERIES
int f_sys_signaldeliver_e(struct event_filler_arguments *args)
{
	int res;

	/*
	 * source pid
	 */
	res = val_to_ring(args, args->spid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * destination pid
	 */
	res = val_to_ring(args, args->dpid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * signal number
	 */
	res = val_to_ring(args, args->signo, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}
#endif

#ifdef CAPTURE_PAGE_FAULTS
int f_sys_pagefault_e(struct event_filler_arguments *args)
{
	int res;

	res = val_to_ring(args, args->fault_data.address, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	res = val_to_ring(args, args->fault_data.regs->ip, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	res = val_to_ring(args, pf_flags_to_scap(args->fault_data.error_code), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}
#endif

int f_cpu_hotplug_e(struct event_filler_arguments *args)
{
	int res;

	/*
	 * cpu
	 */
	res = val_to_ring(args, (uint64_t)args->sched_prev, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * action
	 */
	res = val_to_ring(args, (uint64_t)args->sched_next, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_semop_x(struct event_filler_arguments *args)
{
	unsigned long nsops;
	int res;
	int64_t retval;
	struct sembuf *ptr;

	/*
	 * return value
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * nsops
	 * actually this could be read in the enter function but
	 * we also need to know the value to access the sembuf structs
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &nsops);
	res = val_to_ring(args, nsops, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * sembuf
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, (unsigned long *) &ptr);

	if (nsops && ptr) {
		/* max length of sembuf array in g_event_info = 2 */
		const unsigned max_nsops = 2;
		unsigned       j;

		for (j = 0; j < max_nsops; j++) {
			struct sembuf sops = {0, 0, 0};

			if (nsops--)
				if (unlikely(ppm_copy_from_user(&sops, (void *)&ptr[j], sizeof(struct sembuf))))
					return PPM_FAILURE_INVALID_USER_MEMORY;

			res = val_to_ring(args, sops.sem_num, 0, true, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;

			res = val_to_ring(args, sops.sem_op, 0, true, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;

			res = val_to_ring(args, semop_flags_to_scap(sops.sem_flg), 0, true, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		}
	}

	return add_sentinel(args);
}

int f_sys_semget_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * key
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * nsems
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * semflg
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, semget_flags_to_scap(val), 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_semctl_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * semid
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * semnum
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * cmd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, semctl_cmd_to_scap(val), 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * optional argument semun/val
	 */
	if (val == SETVAL)
		syscall_get_arguments_deprecated(current, args->regs, 3, 1, &val);
	else
		val = 0;
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_access_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, access_flags_to_scap(val), 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_bpf_x(struct event_filler_arguments *args)
{
	int64_t retval;
	unsigned long cmd;
	int res;

	/*
	 * res, if failure or depending on cmd
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	if (retval < 0) {
		res = val_to_ring(args, retval, 0, false, PPM_BPF_IDX_RES);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		return add_sentinel(args);
	}
	/*
	 * fd, depending on cmd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &cmd);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
	if(cmd == BPF_MAP_CREATE || cmd == BPF_PROG_LOAD)
#else
	if(0)
#endif
	{
		res = val_to_ring(args, retval, 0, false, PPM_BPF_IDX_FD);
	}
	else
	{
		res = val_to_ring(args, retval, 0, false, PPM_BPF_IDX_RES);
	}
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_mkdirat_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * path
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_fchmodat_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * filename
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, chmod_mode_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_chmod_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * filename
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, chmod_mode_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

int f_sys_fchmod_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * mode
	 */
	syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, chmod_mode_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}
