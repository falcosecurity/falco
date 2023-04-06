/*
 * Copyright (C) 2021 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

/**
 * @file kernel_hacks.h
 *
 * This file contains kernel-version-dependent preprocessor instructions to
 * help the driver compile on as many kernel versions as possible.
 */

#include <linux/version.h>

/* probe_kernel_read() only added in kernel 2.6.26, name changed in 5.8.0 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
static inline long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
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
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#define copy_from_kernel_nofault probe_kernel_read
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
