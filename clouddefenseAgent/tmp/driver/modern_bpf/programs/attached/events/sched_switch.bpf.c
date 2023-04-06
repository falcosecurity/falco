#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/attached_programs.h>

/* From linux tree: /include/linux/events/sched.h
 * TP_PROTO(bool preempt, struct task_struct *prev,
 *		 struct task_struct *next)
 */
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch,
	     bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	if(sampling_logic(PPME_SCHEDSWITCH_6_E, TRACEPOINT))
	{
		return 0;
	}
	
	/// TODO: we could avoid switches from kernel threads to kernel threads (?).

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SCHED_SWITCH_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SCHEDSWITCH_6_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: next (type: PT_PID) */
	s64 pid = (s64)extract__task_xid_nr(next, PIDTYPE_PID);
	ringbuf__store_s64(&ringbuf, (s64)pid);

	/* Parameter 2: pgft_maj (type: PT_UINT64) */
	unsigned long pgft_maj = 0;
	extract__pgft_maj(prev, &pgft_maj);
	ringbuf__store_u64(&ringbuf, pgft_maj);

	/* Parameter 3: pgft_min (type: PT_UINT64) */
	unsigned long pgft_min = 0;
	extract__pgft_min(prev, &pgft_min);
	ringbuf__store_u64(&ringbuf, pgft_min);

	struct mm_struct *mm = NULL;
	READ_TASK_FIELD_INTO(&mm, prev, mm);

	/* Parameter 4: vm_size (type: PT_UINT32) */
	u32 vm_size = extract__vm_size(mm);
	ringbuf__store_u32(&ringbuf, vm_size);

	/* Parameter 5: vm_rss (type: PT_UINT32) */
	u32 vm_rss = extract__vm_rss(mm);
	ringbuf__store_u32(&ringbuf, vm_rss);

	/* Parameter 6: vm_swap (type: PT_UINT32) */
	u32 vm_swap = extract__vm_swap(mm);
	ringbuf__store_u32(&ringbuf, vm_swap);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}
