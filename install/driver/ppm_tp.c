#include "ppm_tp.h"

const char *tp_names[] = {
#define X(name, path) path,
	TP_FIELDS
#undef X
};

#ifndef __KERNEL__
#include <string.h>
#include "ppm_events_public.h"

typedef struct {
	ppm_sc_code sc_code;
	ppm_tp_code tp_code;
} sc_to_tp_map;

static sc_to_tp_map ppm_sc_to_tp_table[] = {
	{ PPM_SC_SCHED_PROCESS_EXIT, SCHED_PROC_EXIT},
	{ PPM_SC_SCHED_SWITCH, SCHED_SWITCH },
	{ PPM_SC_PAGE_FAULT_USER, PAGE_FAULT_USER },
	{ PPM_SC_PAGE_FAULT_KERNEL, PAGE_FAULT_KERN },
	{ PPM_SC_SIGNAL_DELIVER, SIGNAL_DELIVER },
};

// TODO _Static_assert(sizeof(ppm_sc_to_tp_table) / sizeof(*ppm_sc_to_tp_table) == PPM_SC_TP_LEN, "Wrong number of ppm_sc_to_tp_table entries.");

static inline ppm_tp_code get_tp_from_sc(ppm_sc_code sc)
{
	for (int j = 0; j < sizeof(ppm_sc_to_tp_table) / sizeof(*ppm_sc_to_tp_table); j++)
	{
		if (ppm_sc_to_tp_table[j].sc_code == sc)
		{
			return ppm_sc_to_tp_table[j].tp_code;
		}
	}
	return -1;
}

void tp_set_from_sc_set(const bool *sc_set, bool *tp_set)
{
	memset(tp_set, 0, TP_VAL_MAX * sizeof(*tp_set));
	if (!sc_set)
	{
		for (int i = 0; i < TP_VAL_MAX; i++)
		{
			tp_set[i] = true;
		}
		return;
	}

	for (int i = 0; i < PPM_SC_MAX; i++)
	{
		if (sc_set[i])
		{
			const ppm_tp_code tp = get_tp_from_sc(i);
			if (tp != -1)
			{
				tp_set[tp] = true;
			}
			else
			{
				// It's a syscall and is enabled!
				// Enable sys_enter and sys_exit
				tp_set[SYS_ENTER] = true;
				tp_set[SYS_EXIT] = true;
			}
		}
	}

	/*==============================================================
	 *
	 * Force-set tracepoints that are not mapped to a single event
	 * Ie: PPM_SC_SCHED_PROCESS_FORK, PPM_SC_SCHED_PROCESS_EXEC
	 *
	 *==============================================================*/
	// If users requested CLONE3, CLONE, FORK, VFORK,
	// enable also tracepoint to receive them on arm64
	if (sc_set[PPM_SC_FORK] ||
	   sc_set[PPM_SC_VFORK] ||
	   sc_set[PPM_SC_CLONE] ||
	   sc_set[PPM_SC_CLONE3])
	{
		tp_set[SCHED_PROC_FORK] = true;
	}

	// If users requested EXECVE, EXECVEAT
	// enable also tracepoint to receive them on arm64
	if (sc_set[PPM_SC_EXECVE] ||
	   sc_set[PPM_SC_EXECVEAT])
	{
		tp_set[SCHED_PROC_EXEC] = true;
	}
}
#endif
