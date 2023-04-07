/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(quotactl_e,
	     struct pt_regs *regs,
	     long syscall_id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, QUOTACTL_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_QUOTACTL_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: cmd (type: PT_FLAGS16) */
	uint32_t cmd = (uint32_t)extract__syscall_argument(regs, 0);
	u16 scap_cmd = quotactl_cmd_to_scap(cmd);
	ringbuf__store_u16(&ringbuf, scap_cmd);

	/* Parameter 2: type (type: PT_FLAGS8) */
	ringbuf__store_u8(&ringbuf, quotactl_type_to_scap(cmd));

	/* Parameter 3: id (type: PT_UINT32) */
	u32 id = (u32)extract__syscall_argument(regs, 2);
	if(scap_cmd != PPM_Q_GETQUOTA &&
	   scap_cmd != PPM_Q_SETQUOTA &&
	   scap_cmd != PPM_Q_XGETQUOTA &&
	   scap_cmd != PPM_Q_XSETQLIM)
	{
		/* In this case `id` don't represent a `userid` or a `groupid` */
		ringbuf__store_u32(&ringbuf, 0);
	}
	else
	{
		ringbuf__store_u32(&ringbuf, id);
	}

	/* Parameter 4: quota_fmt (type: PT_FLAGS8) */
	u8 quota_fmt = PPM_QFMT_NOT_USED;
	if(scap_cmd == PPM_Q_QUOTAON)
	{
		quota_fmt = quotactl_fmt_to_scap(id);
	}
	ringbuf__store_u8(&ringbuf, quota_fmt);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(quotactl_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_QUOTACTL_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: special (type: PT_CHARBUF) */
	/* The special argument is a pointer to a null-terminated string
	 * containing the pathname of the (mounted) block special device for
	 * the filesystem being manipulated.
	 */
	unsigned long special_pointer = extract__syscall_argument(regs, 1);
	auxmap__store_charbuf_param(auxmap, special_pointer, MAX_PATH, USER);

	int32_t cmd = (int32_t)extract__syscall_argument(regs, 0);
	u16 scap_cmd = quotactl_cmd_to_scap(cmd);

	/* The `addr` argument is the address of an optional, command-
	 * specific data structure that is copied in or out of the system.
	 * The interpretation of `addr` is given with each cmd.
	 */
	unsigned long addr_pointer = extract__syscall_argument(regs, 3);

	/* We get `quotafilepath` only for `QUOTAON` command. */
	if(scap_cmd == PPM_Q_QUOTAON)
	{
		/* Parameter 3: quotafilepath (type: PT_CHARBUF) */
		auxmap__store_charbuf_param(auxmap, addr_pointer, MAX_PATH, USER);
	}
	else
	{
		/* Parameter 3: quotafilepath (type: PT_CHARBUF) */
		auxmap__store_empty_param(auxmap);
	}

	/* We extract the `struct if_dqblk` if possible. */
	struct if_dqblk dqblk = {0};
	if(scap_cmd == PPM_Q_GETQUOTA || scap_cmd == PPM_Q_SETQUOTA)
	{
		bpf_probe_read_user((void *)&dqblk, bpf_core_type_size(struct if_dqblk), (void *)addr_pointer);
	}

	/* Please note that `dqblk` struct could be filled with values different from `0`,
	 * even if these values are not valid, so we need to explicitly send `0`.
	 */
	if(dqblk.dqb_valid & QIF_BLIMITS)
	{
		/* Parameter 4: dqb_bhardlimit (type: PT_UINT64) */
		auxmap__store_u64_param(auxmap, dqblk.dqb_bhardlimit);

		/* Parameter 5: dqb_bsoftlimit (type: PT_UINT64) */
		auxmap__store_u64_param(auxmap, dqblk.dqb_bsoftlimit);
	}
	else
	{
		/* Parameter 4: dqb_bhardlimit (type: PT_UINT64) */
		auxmap__store_u64_param(auxmap, 0);

		/* Parameter 5: dqb_bsoftlimit (type: PT_UINT64) */
		auxmap__store_u64_param(auxmap, 0);
	}

	if(dqblk.dqb_valid & QIF_SPACE)
	{
		/* Parameter 6: dqb_curspace (type: PT_UINT64) */
		auxmap__store_u64_param(auxmap, dqblk.dqb_curspace);
	}
	else
	{
		/* Parameter 6: dqb_curspace (type: PT_UINT64) */
		auxmap__store_u64_param(auxmap, 0);
	}

	if(dqblk.dqb_valid & QIF_ILIMITS)
	{
		/* Parameter 7: dqb_ihardlimit (type: PT_UINT64) */
		auxmap__store_u64_param(auxmap, dqblk.dqb_ihardlimit);

		/* Parameter 8: dqb_isoftlimit (type: PT_UINT64) */
		auxmap__store_u64_param(auxmap, dqblk.dqb_isoftlimit);
	}
	else
	{
		/* Parameter 7: dqb_ihardlimit (type: PT_UINT64) */
		auxmap__store_u64_param(auxmap, 0);

		/* Parameter 8: dqb_isoftlimit (type: PT_UINT64) */
		auxmap__store_u64_param(auxmap, 0);
	}

	if(dqblk.dqb_valid & QIF_BTIME)
	{
		/* Parameter 9: dqb_btime (type: PT_RELTIME) */
		auxmap__store_u64_param(auxmap, dqblk.dqb_btime);
	}
	else
	{
		/* Parameter 9: dqb_btime (type: PT_RELTIME) */
		auxmap__store_u64_param(auxmap, 0);
	}

	if(dqblk.dqb_valid & QIF_ITIME)
	{
		/* Parameter 10: dqb_itime (type: PT_RELTIME) */
		auxmap__store_u64_param(auxmap, dqblk.dqb_itime);
	}
	else
	{
		/* Parameter 10: dqb_itime (type: PT_RELTIME) */
		auxmap__store_u64_param(auxmap, 0);
	}

	/* We extract the `struct if_dqinfo` if possible. */
	struct if_dqinfo dqinfo = {0};
	if(scap_cmd == PPM_Q_GETINFO || scap_cmd == PPM_Q_SETINFO)
	{
		bpf_probe_read_user((void *)&dqinfo, bpf_core_type_size(struct if_dqinfo), (void *)addr_pointer);
	}

	if(dqinfo.dqi_valid & IIF_BGRACE)
	{
		/* Parameter 11: dqi_bgrace (type: PT_RELTIME) */
		auxmap__store_u64_param(auxmap, dqinfo.dqi_bgrace);
	}
	else
	{
		/* Parameter 11: dqi_bgrace (type: PT_RELTIME) */
		auxmap__store_u64_param(auxmap, 0);
	}

	if(dqinfo.dqi_valid & IIF_IGRACE)
	{
		/* Parameter 12: dqi_igrace (type: PT_RELTIME) */
		auxmap__store_u64_param(auxmap, dqinfo.dqi_igrace);
	}
	else
	{
		/* Parameter 12: dqi_igrace (type: PT_RELTIME) */
		auxmap__store_u64_param(auxmap, 0);
	}

	if(dqinfo.dqi_valid & IIF_FLAGS)
	{
		/* Parameter 13: dqi_flags (type: PT_FLAGS8) */
		auxmap__store_u8_param(auxmap, dqinfo.dqi_flags);
	}
	else
	{
		/* Parameter 13: dqi_flags (type: PT_FLAGS8) */
		auxmap__store_u8_param(auxmap, 0);
	}

	/* Parameter 14: quota_fmt_out (type: PT_FLAGS8) */
	u32 quota_fmt_out = PPM_QFMT_NOT_USED;
	if(scap_cmd == PPM_Q_GETFMT)
	{
		u32 quota_fmt_out_tmp = 0;
		bpf_probe_read_user(&quota_fmt_out_tmp, sizeof(quota_fmt_out_tmp), (void *)addr_pointer);
		quota_fmt_out = quotactl_fmt_to_scap(quota_fmt_out_tmp);
	}
	auxmap__store_u8_param(auxmap, quota_fmt_out);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
