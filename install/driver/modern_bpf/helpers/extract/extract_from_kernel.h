/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/base/maps_getters.h>
#include <helpers/base/read_from_task.h>
#include <driver/ppm_flag_helpers.h>

#ifdef CAPTURE_SOCKETCALL
#include <syscall.h>
#endif

/* Used to convert from page number to KB. */
#define DO_PAGE_SHIFT(x) (x) << (IOC_PAGE_SHIFT - 10)

/* This enum should simplify the capabilities extraction. */
enum capability_type
{
	CAP_INHERITABLE = 0,
	CAP_PERMITTED = 1,
	CAP_EFFECTIVE = 2,
};

/* All the functions that are called in bpf to extract parameters
 * start with the `extract` prefix.
 */

///////////////////////////
// EXTRACT FROM SYSCALLS
///////////////////////////

/**
 * @brief Extract the syscall id starting from the registers
 *
 * @param regs pointer to the struct where we find the arguments
 * @return syscall id
 */
static __always_inline u32 extract__syscall_id(struct pt_regs *regs)
{
#if defined(__TARGET_ARCH_x86)
	return (u32)regs->orig_ax;
#elif defined(__TARGET_ARCH_arm64)
	return (u32)regs->syscallno;
#elif defined(__TARGET_ARCH_s390)
	return (u32)regs->int_code & 0xffff;
#else
	return 0;
#endif
}

/**
 * @brief Extract a specific syscall argument
 *
 * @param regs pointer to the strcut where we find the arguments
 * @param idx index of the argument to extract
 * @return generic unsigned long value that can be a pointer to the arg
 * or directly the value, it depends on the type of arg.
 */
static __always_inline unsigned long extract__syscall_argument(struct pt_regs *regs, int idx)
{
	unsigned long arg;
	switch(idx)
	{
	case 0:
		arg = PT_REGS_PARM1_CORE_SYSCALL(regs);
		break;
	case 1:
		arg = PT_REGS_PARM2_CORE_SYSCALL(regs);
		break;
	case 2:
		arg = PT_REGS_PARM3_CORE_SYSCALL(regs);
		break;
	case 3:
		arg = PT_REGS_PARM4_CORE_SYSCALL(regs);
		break;
	case 4:
		arg = PT_REGS_PARM5_CORE_SYSCALL(regs);
		break;
	case 5:
		/* Not defined in libbpf, look at `definitions_helpers.h` */
		arg = PT_REGS_PARM6_CORE_SYSCALL(regs);
		break;
	default:
		arg = 0;
	}

	return arg;
}

/**
 * @brief Extract one ore more arguments related to a network / socket system call.
 *
 * This function takes into consideration whether the network system call has been
 * called directly (e.g. accept4) or through the socketcall system call multiplexer.
 * For the socketcall multiplexer, arguments are extracted from the second argument
 * of the socketcall system call.  See socketcall(2) for more information.
 *
 * @param argv Pointer to store up to @num arguments of size `unsigned long`
 * @param num Number of arguments to extract
 * @param regs Pointer to the struct pt_regs to access arguments and system call ID
 */
static __always_inline void extract__network_args(void *argv, int num, struct pt_regs *regs)
{
#ifdef CAPTURE_SOCKETCALL
	int id = extract__syscall_id(regs);
	if(id == __NR_socketcall)
	{
		unsigned long args_pointer = extract__syscall_argument(regs, 1);
		bpf_probe_read_user(argv, num * sizeof(unsigned long), (void*)args_pointer);
		return;
	}
#endif
	for (int i = 0; i < num; i++)
	{
		unsigned long *dst = (unsigned long *)argv;
		dst[i] = extract__syscall_argument(regs, i);
	}
}

///////////////////////////
// ENCODE DEVICE NUMBER
///////////////////////////

/**
 * @brief Encode device number with `MAJOR` and `MINOR` MACRO.
 *
 * Please note: **Used only inside this file**.
 *
 * @param dev device number extracted directly from the kernel.
 * @return encoded device number.
 */
static __always_inline dev_t encode_dev(dev_t dev)
{
	unsigned int major = MAJOR(dev);
	unsigned int minor = MINOR(dev);

	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

///////////////////////////
// FILE EXTRACTION
///////////////////////////

/**
 * @brief Return `file` struct from a file descriptor.
 *
 * @param file_descriptor generic file descriptor.
 * @return struct file* pointer to the `struct file` associated with the
 * file descriptor. Return a NULL pointer in case of failure.
 */
static __always_inline struct file *extract__file_struct_from_fd(s32 file_descriptor)
{
	struct file *f = NULL;
	if(file_descriptor >= 0)
	{
		struct file **fds;
		struct task_struct *task = get_current_task();
		READ_TASK_FIELD_INTO(&fds, task, files, fdt, fd);
		bpf_probe_read_kernel(&f, sizeof(struct file *), &fds[file_descriptor]);
	}
	return f;
}

/**
 * \brief Extract the inode number from a file descriptor.
 *
 * @param fd generic file descriptor.
 * @param ino pointer to the inode number we have to fill.
 */
static __always_inline void extract__ino_from_fd(s32 fd, u64 *ino)
{
	struct file *f = extract__file_struct_from_fd(fd);
	if(!f)
	{
		return;
	}

	BPF_CORE_READ_INTO(ino, f, f_inode, i_ino);
}

/**
 * @brief Return the `f_inode` of task exe_file.
 *
 * @param mm pointer to task mm struct.
 * @return `f_inode` of task exe_file.
 */
static __always_inline struct inode *extract__exe_inode_from_task(struct task_struct *task)
{
	return READ_TASK_FIELD(task, mm, exe_file, f_inode);
}

/**
 * @brief Return the `i_ino` from f_inode.
 *
 * @param mm pointer to inode struct.
 * @param ino pointer to the inode number we have to fill.
 * @return `i_ino` from f_inode.
 */
static __always_inline void extract__ino_from_inode(struct inode *f_inode, u64 *ino)
{
	BPF_CORE_READ_INTO(ino, f_inode, i_ino);
}

/**
 * @brief Return epoch in ns from struct timespec64.
 *
 * @param time timespec64 struct.
 * @return epoch in ns.
 */
static __always_inline u64 extract__epoch_ns_from_time(struct timespec64 time)
{
	time64_t tv_sec = time.tv_sec;
	if (tv_sec < 0)
	{
		return 0;
	}
	return (tv_sec * (uint64_t) 1000000000 + time.tv_nsec);
}

/**
 * \brief Extract the device number and the inode number from a file descriptor.
 *
 * @param fd generic file descriptor.
 * @param dev pointer to the device number we have to fill.
 * @param ino pointer to the inode number we have to fill.
 */
static __always_inline void extract__dev_and_ino_from_fd(s32 fd, dev_t *dev, u64 *ino)
{
	struct file *f = extract__file_struct_from_fd(fd);
	if(!f)
	{
		return;
	}

	BPF_CORE_READ_INTO(dev, f, f_inode, i_sb, s_dev);
	*dev = encode_dev(*dev);
	BPF_CORE_READ_INTO(ino, f, f_inode, i_ino);
}

/**
 * @brief Extract the fd rlimit
 *
 * @param task pointer to the task struct.
 * @param fdlimit return value passed by reference.
 */
static __always_inline void extract__fdlimit(struct task_struct *task, unsigned long *fdlimit)
{
	READ_TASK_FIELD_INTO(fdlimit, task, signal, rlim[RLIMIT_NOFILE].rlim_cur);
}

/////////////////////////
// CAPABILITIES EXTRACTION
////////////////////////

/**
 * @brief Extract capabilities
 *
 * Right now we support only 3 types of capabilities:
 * - cap_inheritable
 * - cap_permitted
 * - cap_effective
 *
 * To extract the specific capabilities use the enum defined by us
 * at the beginning of this file:
 * - CAP_INHERITABLE
 * - CAP_PERMITTED
 * - CAP_EFFECTIVE
 *
 * @param task pointer to task struct.
 * @param capability_type type of capability to extract defined by us.
 * @return PPM encoded capability value
 */
static __always_inline u64 extract__capability(struct task_struct *task, enum capability_type capability_type)
{
	kernel_cap_t cap_struct;
	unsigned long capability;

	switch(capability_type)
	{
	case CAP_INHERITABLE:
		READ_TASK_FIELD_INTO(&cap_struct, task, cred, cap_inheritable);
		break;

	case CAP_PERMITTED:
		READ_TASK_FIELD_INTO(&cap_struct, task, cred, cap_permitted);
		break;

	case CAP_EFFECTIVE:
		READ_TASK_FIELD_INTO(&cap_struct, task, cred, cap_effective);
		break;

	default:
		return 0;
		break;
	}

	return capabilities_to_scap(((unsigned long)cap_struct.cap[1] << 32) | cap_struct.cap[0]);
}

/////////////////////////
// PIDS EXTRACION
////////////////////////

/**
 * @brief Return the pid struct according to the pid type chosen.
 *
 * @param task pointer to the task struct.
 * @param type pid type.
 * @return struct pid * pointer to the right pid struct.
 */
static __always_inline struct pid *extract__task_pid_struct(struct task_struct *task, enum pid_type type)
{
	struct pid *task_pid = NULL;
	switch(type)
	{
	/* we cannot take this info from signal struct. */
	case PIDTYPE_PID:
		READ_TASK_FIELD_INTO(&task_pid, task, thread_pid);
		break;
	default:
		READ_TASK_FIELD_INTO(&task_pid, task, signal, pids[type]);
		break;
	}
	return task_pid;
}

/**
 * @brief Returns the pid namespace in which the specified pid was allocated.
 *
 * @param pid pointer to the task pid struct.
 * @return struct pid_namespace* in which the specified pid was allocated.
 */
static __always_inline struct pid_namespace *extract__namespace_of_pid(struct pid *pid)
{
	u32 level = 0;
	struct pid_namespace *ns = NULL;
	if(pid)
	{
		BPF_CORE_READ_INTO(&level, pid, level);
		BPF_CORE_READ_INTO(&ns, pid, numbers[level].ns);
	}
	return ns;
}

/**
 * @brief extract the `xid` (where x can be 'p', 't', ...) according to the
 * `pid struct` passed as parameter.
 *
 * @param pid pointer to the pid struct.
 * @param ns pointer to the namespace struct.
 * @return pid_t id seen from the pid namespace 'ns'.
 */
static __always_inline pid_t extract__xid_nr_seen_by_namespace(struct pid *pid, struct pid_namespace *ns)
{
	struct upid upid = {0};
	pid_t nr = 0;
	unsigned int pid_level = 0;
	unsigned int ns_level = 0;
	BPF_CORE_READ_INTO(&pid_level, pid, level);
	BPF_CORE_READ_INTO(&ns_level, ns, level);

	if(pid && ns_level <= pid_level)
	{
		BPF_CORE_READ_INTO(&upid, pid, numbers[ns_level]);
		if(upid.ns == ns)
		{
			nr = upid.nr;
		}
	}
	return nr;
}

/*
 * Definitions taken from `/include/linux/sched.h`.
 *
 * the helpers to get the task's different pids as they are seen
 * from various namespaces. In all these methods 'nr' stands for 'numeric'.
 *
 * extract_task_(X)id_nr()     : global id, i.e. the id seen from the init namespace;
 * extract_task_(X)id_vnr()    : virtual id, i.e. the id seen from the pid namespace of current.
 *
 */

/**
 * @brief Return the `xid` (where x can be `p`, `tg`, `pp` ...) seen from the
 *  init namespace.
 *
 * @param task pointer to task struct.
 * @param type pid type.
 * @return `xid` seen from the init namespace.
 */
static __always_inline pid_t extract__task_xid_nr(struct task_struct *task, enum pid_type type)
{
	switch(type)
	{
	case PIDTYPE_PID:
		return READ_TASK_FIELD(task, pid);

	case PIDTYPE_TGID:
		return READ_TASK_FIELD(task, tgid);

	case PIDTYPE_PGID:
		return READ_TASK_FIELD(task, real_parent, pid);

	default:
		return 0;
	}
}

/**
 * @brief Return the `xid` (where x can be `p`, `tg`, `pp` ...) seen from the
 *  pid namespace of the current task.
 *
 * @param task pointer to task struct.
 * @param type pid type.
 * @return `xid` seen from the current task pid namespace.
 */
static __always_inline pid_t extract__task_xid_vnr(struct task_struct *task, enum pid_type type)
{
	struct pid *pid_struct = extract__task_pid_struct(task, type);
	struct pid_namespace *pid_namespace_struct = extract__namespace_of_pid(pid_struct);
	return extract__xid_nr_seen_by_namespace(pid_struct, pid_namespace_struct);
}

/**
 * @brief Return the `start_time` of init task struct from pid namespace seen from
 *  pid namespace of the current task. Monotonic time in nanoseconds.
 *
 * @param task pointer to task struct.
 * @param type pid type.
 * @return `start_time` of init task struct from pid namespace seen from current task pid namespace.
 */
static __always_inline u64 extract__task_pidns_start_time(struct task_struct *task, enum pid_type type, long in_childtid)
{
	// only perform lookup when clone/vfork/fork returns 0 (child process / childtid)
	if (in_childtid == 0)
	{
		struct pid *pid_struct = extract__task_pid_struct(task, type);
		struct pid_namespace *pid_namespace = extract__namespace_of_pid(pid_struct);
		return BPF_CORE_READ(pid_namespace, child_reaper, start_time);
	}
	return 0;
}

/////////////////////////
// PAGE INFO EXTRACION
////////////////////////

/**
 * @brief Extract major page fault number
 *
 * @param task pointer to task struct.
 * @param pgft_maj return value passed by reference.
 */
static __always_inline void extract__pgft_maj(struct task_struct *task, unsigned long *pgft_maj)
{
	READ_TASK_FIELD_INTO(pgft_maj, task, maj_flt);
}

/**
 * @brief Extract minor page fault number
 *
 * @param task pointer to task struct.
 * @param pgft_min return value passed by reference.
 */
static __always_inline void extract__pgft_min(struct task_struct *task, unsigned long *pgft_min)
{
	READ_TASK_FIELD_INTO(pgft_min, task, min_flt);
}

/**
 * @brief Extract total page size
 *
 * @param mm pointer to mm_struct.
 * @return number in KB
 */
static __always_inline unsigned long extract__vm_size(struct mm_struct *mm)
{
	unsigned long vm_pages = 0;
	BPF_CORE_READ_INTO(&vm_pages, mm, total_vm);
	return DO_PAGE_SHIFT(vm_pages);
}

/**
 * @brief Extract resident page size
 *
 * @param mm pointer to mm_struct.
 * @return number in KB
 */
static __always_inline unsigned long extract__vm_rss(struct mm_struct *mm)
{
	s64 file_pages = 0;
	s64 anon_pages = 0;
	s64 shmem_pages = 0;

	/* In recent kernel versions (https://github.com/torvalds/linux/commit/f1a7941243c102a44e8847e3b94ff4ff3ec56f25)
	 * `struct mm_rss_stat` doesn't exist anymore.
	 */
	if(bpf_core_type_exists(struct mm_rss_stat))
	{
		BPF_CORE_READ_INTO(&file_pages, mm, rss_stat.count[MM_FILEPAGES].counter);
		BPF_CORE_READ_INTO(&anon_pages, mm, rss_stat.count[MM_ANONPAGES].counter);
		BPF_CORE_READ_INTO(&shmem_pages, mm, rss_stat.count[MM_SHMEMPAGES].counter);
	}
	else
	{
		struct mm_struct___v6_2 *mm_v6_2 = (void *)mm;
		BPF_CORE_READ_INTO(&file_pages, mm_v6_2, rss_stat[MM_FILEPAGES].count);
		BPF_CORE_READ_INTO(&anon_pages, mm_v6_2, rss_stat[MM_ANONPAGES].count);
		BPF_CORE_READ_INTO(&shmem_pages, mm_v6_2, rss_stat[MM_SHMEMPAGES].count);
	}
	return DO_PAGE_SHIFT(file_pages + anon_pages + shmem_pages);
}

/**
 * @brief Extract swap page size
 *
 * @param mm pointer to mm_struct.
 * @return number in KB
 */
static __always_inline unsigned long extract__vm_swap(struct mm_struct *mm)
{
	s64 swap_entries = 0;
	if(bpf_core_type_exists(struct mm_rss_stat))
	{
		BPF_CORE_READ_INTO(&swap_entries, mm, rss_stat.count[MM_SWAPENTS].counter);
	}
	else
	{
		struct mm_struct___v6_2 *mm_v6_2 = (void *)mm;
		BPF_CORE_READ_INTO(&swap_entries, mm_v6_2, rss_stat[MM_SWAPENTS].count);
	}
	return DO_PAGE_SHIFT(swap_entries);
}

/////////////////////////
// TTY EXTRACTION
////////////////////////

/**
 * @brief Extract encoded tty
 *
 * @param task pointer to task_struct.
 * @return encoded tty number
 */
static __always_inline u32 exctract__tty(struct task_struct *task)
{
	struct signal_struct *signal;
	struct tty_struct *tty;
	struct tty_driver *driver;
	int major = 0;
	int minor_start = 0;
	int index = 0;

	/* Direct access of fields w/ READ_TASK_FIELD_INTO or READ_TASK_FIELD can
	cause issues for tty extraction. Adopt approach of incremental lookups and
	checks similar to driver-bpf */

	BPF_CORE_READ_INTO(&signal, task, signal);
	if (!signal)
	{
		return 0;
	}

	BPF_CORE_READ_INTO(&tty, signal, tty);
	if (!tty)
	{
		return 0;
	}

	BPF_CORE_READ_INTO(&driver, tty, driver);
	if (!driver)
	{
		return 0;
	}

	BPF_CORE_READ_INTO(&index, tty, index);
	BPF_CORE_READ_INTO(&major, driver, major);
	BPF_CORE_READ_INTO(&minor_start, driver, minor_start);
	return encode_dev(MKDEV(major, minor_start) + index);
}

/////////////////////////
// LOGINUID EXTRACTION
////////////////////////

/**
 * @brief Extract loginuid
 *
 * @param task pointer to task struct
 * @param loginuid return value by reference
 */
static __always_inline void extract__loginuid(struct task_struct *task, u32 *loginuid)
{
	if(bpf_core_field_exists(task->loginuid))
	{
		READ_TASK_FIELD_INTO(loginuid, task, loginuid.val);
	}
}

/////////////////////////
// EXTRACT CLONE FLAGS
////////////////////////

/**
 * @brief To extract clone flags we need to read some info in the kernel
 *
 * @param task pointer to the task struct.
 * @param flags internal flag representation.
 * @return scap flag representation.
 */
static __always_inline unsigned long extract__clone_flags(struct task_struct *task, unsigned long flags)
{
	unsigned long ppm_flags = clone_flags_to_scap(flags);
	struct pid *pid = extract__task_pid_struct(task, PIDTYPE_PID);
	struct pid_namespace *ns = extract__namespace_of_pid(pid);
	unsigned int ns_level;
	BPF_CORE_READ_INTO(&ns_level, ns, level);

	if(ns_level != 0)
	{
		flags |= PPM_CL_CHILD_IN_PIDNS;
	}
	else
	{
		struct pid_namespace *ns_children;
		READ_TASK_FIELD_INTO(&ns_children, task, nsproxy, pid_ns_for_children);

		if(ns_children != ns)
		{
			flags |= PPM_CL_CHILD_IN_PIDNS;
		}
	}
	return ppm_flags;
}

/////////////////////////
// UID EXTRACTION
////////////////////////

/**
 * @brief Extract euid
 *
 * @param task pointer to task struct
 * @param euid return value by reference
 */
static __always_inline void extract__euid(struct task_struct *task, u32 *euid)
{
	READ_TASK_FIELD_INTO(euid, task, cred, euid.val);
}

/**
 * @brief Extract egid
 *
 * @param task pointer to task struct
 * @param egid return value by reference
 */
static __always_inline void extract__egid(struct task_struct *task, u32 *egid)
{
	READ_TASK_FIELD_INTO(egid, task, cred, egid.val);
}

/////////////////////////
// EXECVE FLAGS EXTRACTION
////////////////////////

static __always_inline bool extract__exe_upper_layer(struct inode *inode)
{
	unsigned long sb_magic = BPF_CORE_READ(inode, i_sb, s_magic);

	if(sb_magic == PPM_OVERLAYFS_SUPER_MAGIC)
	{
		struct dentry *upper_dentry = NULL;
		char *vfs_inode = (char *)inode;
		unsigned long inode_size = bpf_core_type_size(struct inode);
		if(!inode_size)
		{
			return false;
		}

		bpf_probe_read_kernel(&upper_dentry, sizeof(upper_dentry), vfs_inode + inode_size);

		if(upper_dentry)
		{
			return true;
		}
	}

	return false;
}
