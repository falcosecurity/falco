/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/base/common.h>

/* This inline function tries to retrieve the task struct pointer with BTF information enabled.
 * Where not possible it retrieves the normal pointer without BTF info
 * Kernel version required: 5.11.
 */
static __always_inline struct task_struct *get_current_task()
{
	if(bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_current_task_btf)
		&& (bpf_core_enum_value(enum bpf_func_id, BPF_FUNC_get_current_task_btf) == BPF_FUNC_get_current_task_btf))
	{
		return (struct task_struct *)bpf_get_current_task_btf();
	}
	else
	{
		return (struct task_struct *)bpf_get_current_task();
	}
}

/* This macro `READ_TASK_FIELD` allows to try a direct memory access starting from
 * the task struct if the kernel helper `bpf_get_current_task_btf` is available (5.11).
 * N.B. Only up to 9 "field accessors" are supported, which should be more
 * than enough for any practical purpose.
 */
#define READ_TASK_FIELD(src, a, ...)                                                            \
	({                                                                                      \
		___type((src), a, ##__VA_ARGS__) __r;                                           \
		if(bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_current_task_btf) \
			&& (bpf_core_enum_value(enum bpf_func_id, BPF_FUNC_get_current_task_btf) == BPF_FUNC_get_current_task_btf)) \
		{                                                                               \
			__r = ___arrow((src), a, ##__VA_ARGS__);                                \
		}                                                                               \
		else                                                                            \
		{                                                                               \
			BPF_CORE_READ_INTO(&__r, (src), a, ##__VA_ARGS__);                      \
		}                                                                               \
		__r;                                                                            \
	})

/* This macro `READ_TASK_FIELD_INTO` is the equivalent of `BPF_CORE_READ_INTO`.
 * Use this approach when possible. Here we do not define auxiliary variables in the stack.
 * Even if the BPF_CORE_READ_INTO() can return an error value, we do not catch it because
 * with the direct memory access we have no error value. So not use this macro as following:
 *
 * 		...
 * 		int ret = READ_TASK_FIELD_INTO(&status, task, thread_info.status);
 * 		...
 *
 * intead use this approach if you need to check some values:
 *
 * 		...
 *		READ_TASK_FIELD_INTO(&status, task, thread_info.status);
 *      if(!status)
 * 		{
 * 			...
 * 		}
 * 		...
 */
#define READ_TASK_FIELD_INTO(dst, src, a, ...)                                                  \
	({                                                                                      \
		if(bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_current_task_btf) \
			&& (bpf_core_enum_value(enum bpf_func_id, BPF_FUNC_get_current_task_btf) == BPF_FUNC_get_current_task_btf)) \
		{                                                                               \
			*dst = ___arrow((src), a, ##__VA_ARGS__);                               \
		}                                                                               \
		else                                                                            \
		{                                                                               \
			BPF_CORE_READ_INTO(dst, src, a, ##__VA_ARGS__);                         \
		}                                                                               \
	})
