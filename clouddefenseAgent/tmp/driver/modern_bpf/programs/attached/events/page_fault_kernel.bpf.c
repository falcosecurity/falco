/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/attached_programs.h>

/* From linux tree: `/arch/x86/include/asm/trace/exceptions.h`
 *	 TP_PROTO(unsigned long address, struct pt_regs *regs,
 *		unsigned long error_code)
 */
#ifdef CAPTURE_PAGE_FAULTS
SEC("tp_btf/page_fault_kernel")
int BPF_PROG(pf_kernel,
	     unsigned long address, struct pt_regs *regs,
	     unsigned long error_code)
{
	if(sampling_logic(PPME_PAGE_FAULT_E, TRACEPOINT))
	{
		return 0;
	}

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, PAGE_FAULT_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_PAGE_FAULT_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: addr (type: PT_UINT64) */
	ringbuf__store_u64(&ringbuf, address);

	/* Parameter 2: ip (type: PT_UINT64) */
	long unsigned int ip = 0;
	bpf_probe_read_kernel(&ip, sizeof(ip), (void *)regs->ip);
	ringbuf__store_u64(&ringbuf, ip);

	/* Parameter 3: error (type: PT_FLAGS32) */
	ringbuf__store_u32(&ringbuf, pf_flags_to_scap(error_code));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}
#endif
