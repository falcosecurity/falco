#pragma once

/* | name | path | */
#define TP_FIELDS \
	X(SYS_ENTER, "sys_enter")    \
	X(SYS_EXIT, "sys_exit")      \
	X(SCHED_PROC_EXIT, "sched_process_exit")      \
        X(SCHED_SWITCH, "sched_switch")    \
	X(PAGE_FAULT_USER, "page_fault_user")      \
	X(PAGE_FAULT_KERN, "page_fault_kernel")      \
        X(SIGNAL_DELIVER, "signal_deliver")   \
	X(SCHED_PROC_FORK, "sched_process_fork")      \
	X(SCHED_PROC_EXEC, "sched_process_exec")

typedef enum {
#define X(name, path) name,
	TP_FIELDS
#undef X
	TP_VAL_MAX,
} ppm_tp_code;

extern const char *tp_names[];

#ifndef __KERNEL__

#include <stdbool.h>

typedef struct
{
	bool tp[TP_VAL_MAX];
} interesting_ppm_tp_set;

void tp_set_from_sc_set(const bool *sc_set, bool *tp_set);

#ifdef SCAP_HANDLE_T

static int handle_ppm_sc_mask(SCAP_HANDLE_T *handle, bool *sc_set, bool enable, unsigned int ppm_sc,
				  int (*sc_enabler)(SCAP_HANDLE_T *handle, unsigned int sc, bool enable),
				  int (*tp_enabler)(SCAP_HANDLE_T *handle, ppm_tp_code tp, bool enable))
{
	int ret = 0;

	// Load initial tp_set
	bool curr_tp_set[TP_VAL_MAX];
	tp_set_from_sc_set(sc_set, curr_tp_set);

	if (enable)
	{
		if(sc_set[ppm_sc])
		{
			// nothing to do
			return ret;
		}
		sc_set[ppm_sc] = true;
	}
	else
	{
		if(!sc_set[ppm_sc])
		{
			// nothing to do
			return ret;
		}
		sc_set[ppm_sc] = false;
	}

	// This won't do anything if the sc is a syscall
	sc_enabler(handle, ppm_sc, enable);

	// Load final tp_set -> note we must check this for syscalls too
	// because we want to be able to enable/disable sys_{enter,exit} tracepoints dynamically.
	bool final_tp_set[TP_VAL_MAX];
	tp_set_from_sc_set(sc_set, final_tp_set);
	for (int tp = 0; tp < TP_VAL_MAX && ret == 0; tp++)
	{
		if (curr_tp_set[tp] != final_tp_set[tp])
		{
			ret = tp_enabler(handle, tp, final_tp_set[tp]);
		}
	}
	return ret;
}
#endif /* SCAP_HANDLE_T */

#endif /* __KERNEL__ */