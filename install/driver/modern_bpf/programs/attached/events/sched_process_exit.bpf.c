#include <helpers/interfaces/fixed_size_event.h>
#include <driver/systype_compat.h>
#include <helpers/interfaces/attached_programs.h>

/* From linux tree: /include/trace/events/sched.h
 * TP_PROTO(struct task_struct *p)
 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(sched_proc_exit,
	     struct task_struct *task)
{
	if(sampling_logic(PPME_PROCEXIT_1_E, TRACEPOINT))
	{
		return 0;
	}

	uint32_t flags = 0;
	READ_TASK_FIELD_INTO(&flags, task, flags);

	/* We are not interested in kernel threads. */
	if(flags & PF_KTHREAD)
	{
		return 0;
	}

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, PROC_EXIT_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_PROCEXIT_1_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: status (type: PT_ERRNO) */
	s32 exit_code = 0;
	READ_TASK_FIELD_INTO(&exit_code, task, exit_code);
	ringbuf__store_s64(&ringbuf, (s64)exit_code);

	/* Parameter 2: ret (type: PT_ERRNO) */
	s32 ret = __WEXITSTATUS(exit_code);
	ringbuf__store_s64(&ringbuf, (s64)ret);

	/* Parameter 3: sig (type: PT_SIGTYPE) */
	u8 sig = 0;
	/* If the process terminates with a signal collect it. */
	if(__WIFSIGNALED(exit_code) != 0)
	{
		sig = __WTERMSIG(exit_code);
	}
	ringbuf__store_u8(&ringbuf, sig);

	/* Parameter 4: core (type: PT_UINT8) */
	u8 core = __WCOREDUMP(exit_code) != 0;
	ringbuf__store_u8(&ringbuf, core);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}
