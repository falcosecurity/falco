/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#define DRAGENT_WIN_HAL_C_ONLY
#include <dragent_win_hal_public.h>

#include "scap.h"
#include "scap-int.h"
#include "windows_hal.h"

static int32_t addprocess_windows(wh_procinfo* wpi, scap_t* handle, char *error)
{
	struct scap_threadinfo* tinfo;

	//
	//  Allocate the procinfo object.
	//
	if((tinfo = scap_proc_alloc(handle)) == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "addprocess_windows memory allocation error");
		return SCAP_FAILURE;
	}

	//
	// Fill the procinfo object
	//
	memset(tinfo, 0, sizeof(struct scap_threadinfo));

	tinfo->pid = wpi->pid;
	tinfo->tid = wpi->tid;
	tinfo->ptid = wpi->ptid;
	snprintf(tinfo->comm, SCAP_MAX_PATH_SIZE, "%s", wpi->comm);
	snprintf(tinfo->exe, SCAP_MAX_PATH_SIZE, "%s", wpi->exe);
	snprintf(tinfo->exepath, SCAP_MAX_PATH_SIZE, "%s", wpi->exepath);
	snprintf(tinfo->args, SCAP_MAX_PATH_SIZE, "%s", wpi->args);
	tinfo->args_len = wpi->args_len;
	tinfo->vmsize_kb = wpi->vmsize_kb;
	tinfo->pfmajor = wpi->pfmajor;
	tinfo->pfminor = wpi->pfminor;
	tinfo->clone_ts = wpi->clone_ts;
	tinfo->tty = wpi->tty;

	wh_proc_perf_info pinfo = wh_wmi_get_proc_perf_info(handle->m_whh, tinfo->pid);
	if(pinfo.m_result != 0)
	{
		tinfo->vmrss_kb = pinfo.m_memory_bytes / 1024;
		tinfo->vmswap_kb = pinfo.m_swap_bytes / 1024;
	}
	else
	{
		tinfo->vmrss_kb = 0;
		tinfo->vmswap_kb = 0;			
	}
	
	//
	// Done. Add the entry to the process table, or fire the notification callback
	//
	if(handle->m_proc_callback == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "process table construction in scap not supportted on windows");
		return SCAP_FAILURE;

		// int32_t uth_status = SCAP_SUCCESS;

		// HASH_ADD_INT64(handle->m_proclist, pid, tinfo);
		// if(uth_status != SCAP_SUCCESS)
		// {
		// 	snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (2)");
		// 	return SCAP_FAILURE;
		// }
	}
	else
	{
		handle->m_proc_callback(handle->m_proc_callback_context, handle, tinfo->tid, tinfo, NULL);
		free(tinfo);
	}

	return SCAP_SUCCESS;
}

typedef int (CALLBACK* LPFNDLLFUNC1)();

int32_t scap_proc_scan_proc_dir_windows(scap_t* handle, char *error)
{
	wh_proclist wgpres;

	//
	// Get the system processes through WMI
	//
	wgpres = wh_wmi_get_procs(handle->m_whh);
	if(wgpres.m_result == 0)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", wh_getlasterror(handle->m_whh));
		return SCAP_FAILURE;
	}

	//
	// While we're here, refresh the docker state and the process performance table
	//
	if(wh_is_docker_present(handle->m_whh))
	{
		if(wh_docker_refresh(handle->m_whh) == 0)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "%s", wh_getlasterror(handle->m_whh));
			return SCAP_FAILURE;				
		}
	}

	if(wh_wmi_update_procs_perf(handle->m_whh) == 0)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", wh_getlasterror(handle->m_whh));
		return SCAP_FAILURE;
	}

	//
	// Add the received processes to the scap list 
	//
	for(uint32_t j = 0; j < wgpres.m_count; j++)
	{
		wh_procinfo* wpi = &(wgpres.m_procs[j]);

		if(addprocess_windows(wpi, handle, error) != SCAP_SUCCESS)
		{
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}
