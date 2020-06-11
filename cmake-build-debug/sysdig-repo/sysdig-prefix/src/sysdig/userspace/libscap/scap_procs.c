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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAS_CAPTURE
#ifndef CYGWING_AGENT
#include <unistd.h>
#include <sys/param.h>
#include <dirent.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#endif // CYGWING_AGENT
#endif // HAS_CAPTURE

#include "scap.h"
#include "../../driver/ppm_ringbuffer.h"
#include "scap-int.h"
#ifdef CYGWING_AGENT
#include "windows_hal.h"
#endif

#if defined(_WIN64) || defined(WIN64) || defined(_WIN32) || defined(WIN32)
#define strerror_r(errnum, buf, size) strerror_s(buf, size, errnum)
#endif

#if defined(HAS_CAPTURE)
#ifndef CYGWING_AGENT
int32_t scap_proc_fill_cwd(scap_t *handle, char* procdirname, struct scap_threadinfo* tinfo)
{
	int target_res;
	char filename[SCAP_MAX_PATH_SIZE];

	snprintf(filename, sizeof(filename), "%scwd", procdirname);

	target_res = readlink(filename, tinfo->cwd, sizeof(tinfo->cwd) - 1);
	if(target_res <= 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "readlink %s failed (%s)",
			 filename, scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}

	tinfo->cwd[target_res] = '\0';
	return SCAP_SUCCESS;
}

int32_t scap_proc_fill_info_from_stats(scap_t *handle, char* procdirname, struct scap_threadinfo* tinfo)
{
	char filename[SCAP_MAX_PATH_SIZE];
	uint32_t nfound = 0;
	int64_t tmp;
	uint32_t uid;
	uint64_t tgid;
	uint64_t ppid;
	uint64_t vpid;
	uint64_t vtid;
	int64_t sid;
	int64_t pgid;
	int64_t vpgid;
	uint32_t vmsize_kb;
	uint32_t vmrss_kb;
	uint32_t vmswap_kb;
	uint64_t pfmajor;
	uint64_t pfminor;
	int32_t tty;
	char line[512];
	char tmpc;
	char* s;

	tinfo->uid = (uint32_t)-1;
	tinfo->ptid = (uint32_t)-1LL;
	tinfo->sid = 0;
	tinfo->vpgid = 0;
	tinfo->vmsize_kb = 0;
	tinfo->vmrss_kb = 0;
	tinfo->vmswap_kb = 0;
	tinfo->pfmajor = 0;
	tinfo->pfminor = 0;
	tinfo->filtered_out = 0;
	tinfo->tty = 0;

	snprintf(filename, sizeof(filename), "%sstatus", procdirname);

	FILE* f = fopen(filename, "r");
	if(f == NULL)
	{
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "open status file %s failed (%s)",
			 filename, scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(strstr(line, "Tgid") == line)
		{
			nfound++;

			if(sscanf(line, "Tgid: %" PRIu64, &tgid) == 1)
			{
				tinfo->pid = tgid;
			}
			else
			{
				ASSERT(false);
			}
		}
		if(strstr(line, "Uid") == line)
		{
			nfound++;

			if(sscanf(line, "Uid: %" PRIu64 " %" PRIu32, &tmp, &uid) == 2)
			{
				tinfo->uid = uid;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(strstr(line, "Gid") == line)
		{
			nfound++;

			if(sscanf(line, "Gid: %" PRIu64 " %" PRIu32, &tmp, &uid) == 2)
			{
				tinfo->gid = uid;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(strstr(line, "PPid") == line)
		{
			nfound++;

			if(sscanf(line, "PPid: %" PRIu64, &ppid) == 1)
			{
				tinfo->ptid = ppid;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(strstr(line, "VmSize:") == line)
		{
			nfound++;

			if(sscanf(line, "VmSize: %" PRIu32, &vmsize_kb) == 1)
			{
				tinfo->vmsize_kb = vmsize_kb;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(strstr(line, "VmRSS:") == line)
		{
			nfound++;

			if(sscanf(line, "VmRSS: %" PRIu32, &vmrss_kb) == 1)
			{
				tinfo->vmrss_kb = vmrss_kb;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(strstr(line, "VmSwap:") == line)
		{
			nfound++;

			if(sscanf(line, "VmSwap: %" PRIu32, &vmswap_kb) == 1)
			{
				tinfo->vmswap_kb = vmswap_kb;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(strstr(line, "NSpid:") == line)
		{
			nfound++;
			if(sscanf(line, "NSpid: %*u %" PRIu64, &vtid) == 1)
			{
				tinfo->vtid = vtid;
			}
			else
			{
				tinfo->vtid = tinfo->tid;
			}
		}
		else if(strstr(line, "NSpgid:") == line)
		{
			nfound++;
			if(sscanf(line, "NSpgid: %*u %" PRIu64, &vpgid) == 1)
			{
				tinfo->vpgid = vpgid;
			}
		}
		else if(strstr(line, "NStgid:") == line)
		{
			nfound++;
			if(sscanf(line, "NStgid: %*u %" PRIu64, &vpid) == 1)
			{
				tinfo->vpid = vpid;
			}
			else
			{
				tinfo->vpid = tinfo->pid;
			}
		}

		if(nfound == 10)
		{
			break;
		}
	}

	ASSERT(nfound == 10 || nfound == 7 || nfound == 6);

	fclose(f);

	snprintf(filename, sizeof(filename), "%sstat", procdirname);

	f = fopen(filename, "r");
	if(f == NULL)
	{
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "read stat file %s failed (%s)",
			 filename, scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}

	size_t ssres = fread(line, 1, sizeof(line) - 1, f);
	if(ssres == 0)
	{
		ASSERT(false);
		fclose(f);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not read from stat file %s (%s)",
			 filename, scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}
	line[ssres] = 0;

	s = strrchr(line, ')');
	if(s == NULL)
	{
		ASSERT(false);
		fclose(f);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not find closing bracket in stat file %s",
			 filename);
		return SCAP_FAILURE;
	}

	//
	// Extract the line content
	//
	if(sscanf(s + 2, "%c %" PRId64 " %" PRId64 " %" PRId64 " %" PRId32 " %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64,
		&tmpc,
		&tmp,
		&pgid,
		&sid,
		&tty,
		&tmp,
		&tmp,
		&pfminor,
		&tmp,
		&pfmajor) != 10)
	{
		ASSERT(false);
		fclose(f);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not read expected fields from stat file %s",
			 filename);
		return SCAP_FAILURE;
	}

	tinfo->pfmajor = pfmajor;
	tinfo->pfminor = pfminor;
	tinfo->sid = (uint64_t) sid;

	// If we did not find vpgid above, set it to pgid from the
	// global namespace.
	if(tinfo->vpgid == 0)
	{
		tinfo->vpgid = pgid;
	}

	tinfo->tty = tty;

	fclose(f);
	return SCAP_SUCCESS;
}

//
// use prlimit to extract the RLIMIT_NOFILE for the tid. On systems where prlimit
// is not supported, just return -1
//
static int32_t scap_proc_fill_flimit(scap_t *handle, uint64_t tid, struct scap_threadinfo* tinfo)
#ifdef SYS_prlimit64
{
	struct rlimit rl;

#ifdef __NR_prlimit64
	if(syscall(SYS_prlimit64, tid, RLIMIT_NOFILE, NULL, &rl) == 0)
	{
		tinfo->fdlimit = rl.rlim_cur;
		return SCAP_SUCCESS;
	}
#endif

	tinfo->fdlimit = -1;
	return SCAP_SUCCESS;
}
#else
{
	tinfo->fdlimit = -1;
	return SCAP_SUCCESS;
}
#endif

int32_t scap_proc_fill_cgroups(scap_t *handle, struct scap_threadinfo* tinfo, const char* procdirname)
{
	char filename[SCAP_MAX_PATH_SIZE];
	char line[SCAP_MAX_CGROUPS_SIZE];

	tinfo->cgroups_len = 0;
	snprintf(filename, sizeof(filename), "%scgroup", procdirname);

    if(access(filename, R_OK) == -1)
	{
		return SCAP_SUCCESS;
	}

	FILE* f = fopen(filename, "r");
	if(f == NULL)
	{
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "open cgroup file %s failed (%s)",
			 filename, scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		char* token;
		char* subsys_list;
		char* cgroup;
		char* scratch;

		// id
		token = strtok_r(line, ":", &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			fclose(f);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Did not find id in cgroup file %s",
				 filename);
			return SCAP_FAILURE;
		}

		// subsys
		subsys_list = strtok_r(NULL, ":", &scratch);
		if(subsys_list == NULL)
		{
			ASSERT(false);
			fclose(f);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Did not find subsys in cgroup file %s",
				 filename);
			return SCAP_FAILURE;
		}

		// Hack to detect empty fields, because strtok does not support it
		// strsep() should be used to fix this but it's not available
		// on CentOS 6 (has been added from Glibc 2.19)
		if(subsys_list-token-strlen(token) > 1)
		{
			// skip cgroups like this:
			// 0::/init.scope
			continue;
		}

		// cgroup
		cgroup = strtok_r(NULL, ":", &scratch);
		if(cgroup == NULL)
		{
			ASSERT(false);
			fclose(f);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Did not find cgroup in cgroup file %s",
				 filename);
			return SCAP_FAILURE;
		}

		// remove the \n
		cgroup[strlen(cgroup) - 1] = 0;

		while((token = strtok_r(subsys_list, ",", &scratch)) != NULL)
		{
			subsys_list = NULL;
			if(strlen(cgroup) + 1 + strlen(token) + 1 > SCAP_MAX_CGROUPS_SIZE - tinfo->cgroups_len)
			{
				ASSERT(false);
				fclose(f);
				return SCAP_SUCCESS;
			}

			snprintf(tinfo->cgroups + tinfo->cgroups_len, SCAP_MAX_CGROUPS_SIZE - tinfo->cgroups_len, "%s=%s", token, cgroup);
			tinfo->cgroups_len += strlen(cgroup) + 1 + strlen(token) + 1;
		}
	}

	fclose(f);
	return SCAP_SUCCESS;
}

static int32_t scap_get_vtid(scap_t* handle, int64_t tid, int64_t *vtid)
{
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Cannot get vtid (not in live mode)");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE)
	ASSERT(false)
	return SCAP_FAILURE;
#else

	if(handle->m_bpf)
	{
		*vtid = 0;
	}
	else
	{
		*vtid = ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_GET_VTID, tid);

		if(*vtid == -1)
		{
			ASSERT(false);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "ioctl to get vtid failed (%s)",
				 scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
#endif
}

static int32_t scap_get_vpid(scap_t* handle, int64_t tid, int64_t *vpid)
{
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Cannot get vtid (not in live mode)");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE)
	ASSERT(false)
	return SCAP_FAILURE;
#else

	if(handle->m_bpf)
	{
		*vpid = 0;
	}
	else
	{
		*vpid = ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_GET_VPID, tid);

		if(*vpid == -1)
		{
			ASSERT(false);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "ioctl to get vpid failed (%s)",
				 scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
#endif
}

int32_t scap_proc_fill_root(scap_t *handle, struct scap_threadinfo* tinfo, const char* procdirname)
{
	char root_path[SCAP_MAX_PATH_SIZE];
	snprintf(root_path, sizeof(root_path), "%sroot", procdirname);
	if ( readlink(root_path, tinfo->root, sizeof(tinfo->root)) > 0)
	{
		return SCAP_SUCCESS;
	}
	else
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "readlink %s failed (%s)",
			 root_path, scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}
}

int32_t scap_proc_fill_loginuid(scap_t *handle, struct scap_threadinfo* tinfo, const char* procdirname)
{
	uint32_t loginuid;
	char loginuid_path[SCAP_MAX_PATH_SIZE];
	char line[512];
	snprintf(loginuid_path, sizeof(loginuid_path), "%sloginuid", procdirname);
	FILE* f = fopen(loginuid_path, "r");
	if(f == NULL)
	{
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Open loginuid file %s failed (%s)",
			 loginuid_path, scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}
	if (fgets(line, sizeof(line), f) == NULL)
	{
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not read loginuid from %s (%s)",
			 loginuid_path, scap_strerror(handle, errno));
		fclose(f);
		return SCAP_FAILURE;
	}

	fclose(f);

	if(sscanf(line, "%" PRId32, &loginuid) == 1)
	{
		tinfo->loginuid = loginuid;
		return SCAP_SUCCESS;
	}
	else
	{
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not read loginuid from %s",
			 loginuid_path);
		return SCAP_FAILURE;
	}
}

//
// Add a process to the list by parsing its entry under /proc
//
static int32_t scap_proc_add_from_proc(scap_t* handle, uint32_t tid, char* procdirname, struct scap_ns_socket_list** sockets_by_ns, scap_threadinfo** procinfo, char *error)
{
	char dir_name[256];
	char target_name[SCAP_MAX_PATH_SIZE];
	int target_res;
	char filename[252];
	char line[SCAP_MAX_ENV_SIZE];
	struct scap_threadinfo* tinfo;
	int32_t uth_status = SCAP_SUCCESS;
	FILE* f;
	size_t filesize;
	size_t exe_len;
	bool free_tinfo = false;
	int32_t res = SCAP_SUCCESS;
	struct stat dirstat;

	snprintf(dir_name, sizeof(dir_name), "%s/%u/", procdirname, tid);
	snprintf(filename, sizeof(filename), "%sexe", dir_name);

	//
	// Gather the executable full name
	//
	target_res = readlink(filename, target_name, sizeof(target_name) - 1);			// Getting the target of the exe, i.e. to which binary it points to

	if(target_res <= 0)
	{
		//
		// No exe. This either
		//  - a kernel thread (if there is no cmdline). In that case we skip it.
		//  - a process that has been containerized or has some weird thing going on. In that case
		//    we accept it.
		//
		snprintf(filename, sizeof(filename), "%scmdline", dir_name);
		f = fopen(filename, "r");
		if(f == NULL)
		{
			return SCAP_SUCCESS;
		}

		ASSERT(sizeof(line) >= SCAP_MAX_PATH_SIZE);

		if(fgets(line, SCAP_MAX_PATH_SIZE, f) == NULL)
		{
			fclose(f);
			return SCAP_SUCCESS;
		}
		else
		{
			fclose(f);
		}

		target_name[0] = 0;
	}
	else
	{
		// null-terminate target_name (readlink() does not append a null byte)
		target_name[target_res] = 0;
	}

	//
	// This is a real user level process. Allocate the procinfo structure.
	//
	if((tinfo = scap_proc_alloc(handle)) == NULL)
	{
		// Error message saved in handle->m_lasterr
		snprintf(error, SCAP_LASTERR_SIZE, "can't allocate procinfo struct: %s", handle->m_lasterr);
		return SCAP_FAILURE;
	}

	tinfo->tid = tid;

	tinfo->fdlist = NULL;

	//
	// Gathers the exepath
	//
	snprintf(tinfo->exepath, sizeof(tinfo->exepath), "%s", target_name);

	//
	// Gather the command name
	//
	snprintf(filename, sizeof(filename), "%sstatus", dir_name);

	f = fopen(filename, "r");
	if(f == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't open %s (error %s)", filename, scap_strerror(handle, errno));
		free(tinfo);
		return SCAP_FAILURE;
	}
	else
	{
		ASSERT(sizeof(line) >= SCAP_MAX_PATH_SIZE);

		if(fgets(line, SCAP_MAX_PATH_SIZE, f) == NULL)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "can't read from %s (%s)",
				 filename, scap_strerror(handle, errno));
			fclose(f);
			free(tinfo);
			return SCAP_FAILURE;
		}

		line[SCAP_MAX_PATH_SIZE - 1] = 0;
		sscanf(line, "Name:%1024s", tinfo->comm);
		fclose(f);
	}

	bool suppressed;
	if ((res = scap_update_suppressed(handle, tinfo->comm, tid, 0, &suppressed)) != SCAP_SUCCESS)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't update set of suppressed tids (%s)", handle->m_lasterr);
		free(tinfo);
		return res;
	}

	if (suppressed && !procinfo)
	{
		free(tinfo);
		return SCAP_SUCCESS;
	}

	//
	// Gather the command line
	//
	snprintf(filename, sizeof(filename), "%scmdline", dir_name);

	f = fopen(filename, "r");
	if(f == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't open cmdline file %s (%s)",
			 filename, scap_strerror(handle, errno));
		free(tinfo);
		return SCAP_FAILURE;
	}
	else
	{
		ASSERT(sizeof(line) >= SCAP_MAX_ARGS_SIZE);

		filesize = fread(line, 1, SCAP_MAX_ARGS_SIZE - 1, f);
		if(filesize > 0)
		{
			line[filesize] = 0;

			exe_len = strlen(line);
			if(exe_len < filesize)
			{
				++exe_len;
			}

			snprintf(tinfo->exe, SCAP_MAX_PATH_SIZE, "%s", line);

			tinfo->args_len = filesize - exe_len;

			memcpy(tinfo->args, line + exe_len, tinfo->args_len);
			tinfo->args[SCAP_MAX_ARGS_SIZE - 1] = 0;
		}
		else
		{
			tinfo->args[0] = 0;
			tinfo->exe[0] = 0;
		}

		fclose(f);
	}

	//
	// Gather the environment
	//
	snprintf(filename, sizeof(filename), "%senviron", dir_name);

	f = fopen(filename, "r");
	if(f == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't open environ file %s (%s)",
			 filename, scap_strerror(handle, errno));
		free(tinfo);
		return SCAP_FAILURE;
	}
	else
	{
		ASSERT(sizeof(line) >= SCAP_MAX_ENV_SIZE);

		filesize = fread(line, 1, SCAP_MAX_ENV_SIZE, f);

		if(filesize > 0)
		{
			line[filesize - 1] = 0;

			tinfo->env_len = filesize;

			memcpy(tinfo->env, line, tinfo->env_len);
			tinfo->env[SCAP_MAX_ENV_SIZE - 1] = 0;
		}
		else
		{
			tinfo->env[0] = 0;
		}

		fclose(f);
	}

	//
	// set the current working directory of the process
	//
	if(SCAP_FAILURE == scap_proc_fill_cwd(handle, dir_name, tinfo))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't fill cwd for %s (%s)",
			 dir_name, handle->m_lasterr);
		free(tinfo);
		return SCAP_FAILURE;
	}

	//
	// extract the user id and ppid from /proc/pid/status
	//
	if(SCAP_FAILURE == scap_proc_fill_info_from_stats(handle, dir_name, tinfo))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't fill cwd for %s (%s)",
			 dir_name, handle->m_lasterr);
		free(tinfo);
		return SCAP_FAILURE;
	}

	//
	// Set the file limit
	//
	if(SCAP_FAILURE == scap_proc_fill_flimit(handle, tinfo->tid, tinfo))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't fill flimit for %s (%s)",
			 dir_name, handle->m_lasterr);
		free(tinfo);
		return SCAP_FAILURE;
	}

	if(scap_proc_fill_cgroups(handle, tinfo, dir_name) == SCAP_FAILURE)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't fill cgroups for %s (%s)",
			 dir_name, handle->m_lasterr);
		free(tinfo);
		return SCAP_FAILURE;
	}

	// These values should be read already from /status file, leave these
	// fallback functions for older kernels < 4.1
	if(tinfo->vtid == 0 && scap_get_vtid(handle, tinfo->tid, &tinfo->vtid) == SCAP_FAILURE)
	{
		tinfo->vtid = tinfo->tid;
	}

	if(tinfo->vpid == 0 && scap_get_vpid(handle, tinfo->tid, &tinfo->vpid) == SCAP_FAILURE)
	{
		tinfo->vpid = tinfo->pid;
	}

	//
	// set the current root of the process
	//
	if(SCAP_FAILURE == scap_proc_fill_root(handle, tinfo, dir_name))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't fill root for %s (%s)",
			 dir_name, handle->m_lasterr);
		free(tinfo);
		return SCAP_FAILURE;
	}

	//
	// set the loginuid
	//
	if(SCAP_FAILURE == scap_proc_fill_loginuid(handle, tinfo, dir_name))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't fill loginuid for %s (%s)",
			 dir_name, handle->m_lasterr);
		free(tinfo);
		return SCAP_FAILURE;
	}

	if(stat(dir_name, &dirstat) == 0)
	{
		tinfo->clone_ts = dirstat.st_ctim.tv_sec*1000000000 + dirstat.st_ctim.tv_nsec;
	}

	// If tid is different from pid, assume this is a thread and that the FDs are shared, and set the
	// corresponding process flags.
	// XXX we should see if the process creation flags are stored somewhere in /proc and handle this
	// properly instead of making assumptions.
	//
	if(tinfo->tid == tinfo->pid)
	{
		tinfo->flags = 0;
	}
	else
	{
		tinfo->flags = PPM_CL_CLONE_THREAD | PPM_CL_CLONE_FILES;
	}

	//
	// if procinfo is set we assume this is a runtime lookup so no
	// need to use the table
	//
	if(!procinfo)
	{
		//
		// Done. Add the entry to the process table, or fire the notification callback
		//
		if(handle->m_proc_callback == NULL)
		{
			HASH_ADD_INT64(handle->m_proclist, tid, tinfo);
			if(uth_status != SCAP_SUCCESS)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (2)");
				free(tinfo);
				return SCAP_FAILURE;
			}
		}
		else
		{
			handle->m_proc_callback(handle->m_proc_callback_context, handle, tinfo->tid, tinfo, NULL);
			free_tinfo = true;
		}
	}
	else
	{
		*procinfo = tinfo;
	}

	//
	// Only add fds for processes, not threads
	//
	if(tinfo->pid == tinfo->tid)
	{
		res = scap_fd_scan_fd_dir(handle, dir_name, tinfo, sockets_by_ns, error);
	}

	if(free_tinfo)
	{
		free(tinfo);
	}

	return res;
}

//
// Read a single thread info from /proc
//
int32_t scap_proc_read_thread(scap_t* handle, char* procdirname, uint64_t tid, struct scap_threadinfo** pi, char *error, bool scan_sockets)
{
	struct scap_ns_socket_list* sockets_by_ns = NULL;

	int32_t res;
	char add_error[SCAP_LASTERR_SIZE];

	if(!scan_sockets)
	{
		sockets_by_ns = (void*)-1;
	}

	res = scap_proc_add_from_proc(handle, tid, procdirname, &sockets_by_ns, pi, add_error);
	if(res != SCAP_SUCCESS)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "cannot add proc tid = %"PRIu64", dirname = %s, error=%s", tid, procdirname, add_error);
	}

	if(sockets_by_ns != NULL && sockets_by_ns != (void*)-1)
	{
		scap_fd_free_ns_sockets_list(handle, &sockets_by_ns);
	}

	return res;
}

//
// Scan a directory containing multiple processes under /proc
//
static int32_t _scap_proc_scan_proc_dir_impl(scap_t* handle, char* procdirname, int parenttid, char *error)
{
	DIR *dir_p;
	struct dirent *dir_entry_p;
	scap_threadinfo* tinfo;
	uint64_t tid;
	int32_t res = SCAP_SUCCESS;
	char childdir[SCAP_MAX_PATH_SIZE];

	struct scap_ns_socket_list* sockets_by_ns = NULL;

	dir_p = opendir(procdirname);

	if(dir_p == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error opening the %s directory (%s)",
			 procdirname, scap_strerror(handle, errno));
		return SCAP_NOTFOUND;
	}

	while((dir_entry_p = readdir(dir_p)) != NULL)
	{
		if(strspn(dir_entry_p->d_name, "0123456789") != strlen(dir_entry_p->d_name))
		{
			continue;
		}

		//
		// Gather the process TID, which is the directory name
		//
		tid = atoi(dir_entry_p->d_name);

		//
		// Skip the main thread entry
		//
		if(parenttid != -1 && tid == parenttid)
		{
			continue;
		}

		//
		// This is the initial /proc scan so duplicate threads
		// are an error, or at least unexpected. Check the process
		// list to see if we've encountered this tid already
		//
		HASH_FIND_INT64(handle->m_proclist, &tid, tinfo);
		if(tinfo != NULL)
		{
			ASSERT(false);
			snprintf(error, SCAP_LASTERR_SIZE, "duplicate process %"PRIu64, tid);
			res = SCAP_FAILURE;
			break;
		}

		char add_error[SCAP_LASTERR_SIZE];

		//
		// We have a process that needs to be explored
		//
		res = scap_proc_add_from_proc(handle, tid, procdirname, &sockets_by_ns, NULL, add_error);
		if(res != SCAP_SUCCESS)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "cannot add procs tid = %"PRIu64", parenttid = %"PRIi32", dirname = %s, error=%s", tid, parenttid, procdirname, add_error);
			break;
		}

		//
		// See if this process includes tasks that need to be added
		//
		if(parenttid == -1 && handle->m_mode != SCAP_MODE_NODRIVER)
		{
			snprintf(childdir, sizeof(childdir), "%s/%u/task", procdirname, (int)tid);
			if(_scap_proc_scan_proc_dir_impl(handle, childdir, tid, error) == SCAP_FAILURE)
			{
				res = SCAP_FAILURE;
				break;
			}
		}
	}

	closedir(dir_p);
	if(sockets_by_ns != NULL && sockets_by_ns != (void*)-1)
	{
		scap_fd_free_ns_sockets_list(handle, &sockets_by_ns);
	}
	return res;
}

int32_t scap_proc_scan_proc_dir(scap_t* handle, char* procdirname, char *error)
{
	return _scap_proc_scan_proc_dir_impl(handle, procdirname, -1, error);
}

#endif // CYGWING_AGENT

int32_t scap_getpid_global(scap_t* handle, int64_t* pid)
{
#ifndef CYGWING_AGENT
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Cannot get pid (not in live mode)");
		ASSERT(false);
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE)
	ASSERT(false);
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Cannot get pid (capture not enabled)");
	return SCAP_FAILURE;
#else

	if(handle->m_bpf)
	{
		char filename[SCAP_MAX_PATH_SIZE];
		char line[512];

		snprintf(filename, sizeof(filename), "%s/proc/self/status", scap_get_host_root());

		FILE* f = fopen(filename, "r");
		if(f == NULL)
		{
			ASSERT(false);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can not open status file %s (%s)",
				 filename, scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}

		while(fgets(line, sizeof(line), f) != NULL)
		{
			if(sscanf(line, "Tgid: %" PRId64, pid) == 1)
			{
				fclose(f);
				return SCAP_SUCCESS;
			}
		}

		fclose(f);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "could not find tgid in status file %s",
			 filename);
		return SCAP_FAILURE;
	}
	else
	{
		*pid = ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_GET_CURRENT_PID);
		if(*pid == -1)
		{
			ASSERT(false);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "ioctl to get pid failed (%s)",
				 scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
#endif
#else // CYGWING_AGENT
	return getpid();
#endif // CYGWING_AGENT
}

#endif // HAS_CAPTURE

#ifdef CYGWING_AGENT
int32_t scap_proc_scan_proc_dir(scap_t* handle, char* procdirname, char *error)
{
	return scap_proc_scan_proc_dir_windows(handle, error);
}
#endif

//
// Delete a process entry
//
void scap_proc_delete(scap_t* handle, scap_threadinfo* proc)
{
	//
	// First, free the fd table for this process descriptor
	//
	scap_fd_free_proc_fd_table(handle, proc);

	//
	// Second, remove the process descriptor from the table
	//
	HASH_DEL(handle->m_proclist, proc);

	//
	// Third, free the memory
	//
	free(proc);
}

//
// Free the process table
//
void scap_proc_free_table(scap_t* handle)
{
	struct scap_threadinfo* tinfo;
	struct scap_threadinfo* ttinfo;

	HASH_ITER(hh, handle->m_proclist, tinfo, ttinfo)
	{
		scap_proc_delete(handle, tinfo);
	}
}

struct scap_threadinfo* scap_proc_get(scap_t* handle, int64_t tid, bool scan_sockets)
{
#if !defined(HAS_CAPTURE)
	return NULL;
#else

	//
	// No /proc parsing for offline captures
	//
	if(handle->m_mode == SCAP_MODE_CAPTURE)
	{
		return NULL;
	}

	struct scap_threadinfo* tinfo = NULL;
	char filename[SCAP_MAX_PATH_SIZE];
	snprintf(filename, sizeof(filename), "%s/proc", scap_get_host_root());
	if(scap_proc_read_thread(handle, filename, tid, &tinfo, handle->m_lasterr, scan_sockets) != SCAP_SUCCESS)
	{
		free(tinfo);
		return NULL;
	}

	return tinfo;
#endif // HAS_CAPTURE
}

bool scap_is_thread_alive(scap_t* handle, int64_t pid, int64_t tid, const char* comm)
{
#if !defined(HAS_CAPTURE)
	return false;
#else
	char charbuf[SCAP_MAX_PATH_SIZE];
	FILE* f;


	//
	// No /proc parsing for offline captures
	//
	if(handle->m_mode == SCAP_MODE_CAPTURE)
	{
		return false;
	}

	snprintf(charbuf, sizeof(charbuf), "%s/proc/%" PRId64 "/task/%" PRId64 "/comm", scap_get_host_root(), pid, tid);

	f = fopen(charbuf, "r");

	if(f != NULL)
	{
		if(fgets(charbuf, sizeof(charbuf), f) != NULL)
		{
			if(strncmp(charbuf, comm, strlen(comm)) == 0)
			{
				fclose(f);
				return true;
			}
		}

		fclose(f);
	}
	else
	{
		//
		// If /proc/<pid>/task/<tid>/comm does not exist but /proc/<pid>/task/<tid>/exe does exist, we assume we're on an ancient
		// OS like RHEL5 and we return true.
		// This could generate some false positives on such old distros, and we're going to accept it.
		//
		snprintf(charbuf, sizeof(charbuf), "%s/proc/%" PRId64 "/task/%" PRId64 "/exe", scap_get_host_root(), pid, tid);
		f = fopen(charbuf, "r");
		if(f != NULL)
		{
			fclose(f);
			return true;
		}

	}

	return false;
#endif // HAS_CAPTURE
}

#if defined(HAS_CAPTURE)
int scap_proc_scan_proc_table(scap_t *handle)
{
	char filename[SCAP_MAX_PATH_SIZE];
	//
	// Create the process list
	//
	handle->m_lasterr[0] = '\0';

	snprintf(filename, sizeof(filename), "%s/proc", scap_get_host_root());
	return scap_proc_scan_proc_dir(handle, filename, handle->m_lasterr);
}

void scap_refresh_proc_table(scap_t* handle)
{
	if(handle->m_proclist)
	{
		scap_proc_free_table(handle);
		handle->m_proclist = NULL;
	}
	scap_proc_scan_proc_table(handle);
}
#else
void scap_refresh_proc_table(scap_t* handle)
{
}
#endif // HAS_CAPTURE

struct scap_threadinfo *scap_proc_alloc(scap_t *handle)
{
	struct scap_threadinfo *tinfo = (struct scap_threadinfo*) calloc(1, sizeof(scap_threadinfo));
	if(tinfo == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "process table allocation error (1)");
		return NULL;
	}

	return tinfo;
}

void scap_proc_free(scap_t* handle, struct scap_threadinfo* proc)
{
	scap_fd_free_proc_fd_table(handle, proc);
	free(proc);
}

int32_t scap_proc_add(scap_t* handle, uint64_t tid, scap_threadinfo* tinfo)
{
	int32_t uth_status = SCAP_SUCCESS;

	HASH_ADD_INT64(handle->m_proclist, tid, tinfo);
	if(uth_status == SCAP_SUCCESS)
	{
		return SCAP_SUCCESS;
	}
	else
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not add tid to hash table");
		return SCAP_FAILURE;
	}
}

int32_t scap_fd_add(scap_t *handle, scap_threadinfo* tinfo, uint64_t fd, scap_fdinfo* fdinfo)
{
	int32_t uth_status = SCAP_SUCCESS;

	HASH_ADD_INT64(tinfo->fdlist, fd, fdinfo);
	if(uth_status == SCAP_SUCCESS)
	{
		return SCAP_SUCCESS;
	}
	else
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not add fd to hash table");
		return SCAP_FAILURE;
	}
}

//
// Internal helper functions to output the process table to screen
//
void scap_proc_print_info(scap_t *handle, scap_threadinfo* tinfo)
{
	fprintf(stderr, "TID:%"PRIu64" PID:%"PRIu64" FLAGS:%"PRIu32" COMM:%s EXE:%s ARGS:%s CWD:%s FLIMIT:%" PRId64 "\n", tinfo->tid, tinfo->pid, tinfo->flags,tinfo->comm, tinfo->exe, tinfo->args, tinfo->cwd, tinfo->fdlimit);
	scap_fd_print_table(handle, tinfo);
}

void scap_proc_print_proc_by_tid(scap_t* handle, uint64_t tid)
{
	scap_threadinfo* tinfo;
	scap_threadinfo* ttinfo;

	HASH_ITER(hh, handle->m_proclist, tinfo, ttinfo)
	{
		if(tinfo->tid == tid)
		{
			scap_proc_print_info(handle, tinfo);
		}
	}
}

void scap_proc_print_table(scap_t* handle)
{
	scap_threadinfo* tinfo;
	scap_threadinfo* ttinfo;

	printf("************** PROCESS TABLE **************\n");

	HASH_ITER(hh, handle->m_proclist, tinfo, ttinfo)
	{
		scap_proc_print_info(handle, tinfo);
	}

	printf("*******************************************\n");
}

const char *scap_strerror(scap_t *handle, int errnum)
{
	int rc;
	if((rc = strerror_r(errnum, handle->m_strerror_buf, SCAP_LASTERR_SIZE) != 0))
	{
		if(rc != ERANGE)
		{
			snprintf(handle->m_strerror_buf, SCAP_LASTERR_SIZE, "Errno %d", errnum);
		}
	}

	return handle->m_strerror_buf;
}

int32_t scap_update_suppressed(scap_t *handle,
			       const char *comm,
			       uint64_t tid, uint64_t ptid,
			       bool *suppressed)
{
	uint32_t i;
	scap_tid *stid;

	*suppressed = false;

	HASH_FIND_INT64(handle->m_suppressed_tids, &ptid, stid);

	if(stid != NULL)
	{
		*suppressed = true;
	}
	else
	{
		for(i=0; i < handle->m_num_suppressed_comms; i++)
		{
			if(strcmp(handle->m_suppressed_comms[i], comm) == 0)
			{
				*suppressed = true;
				break;
			}
		}
	}

	// Also check to see if the tid is already in the set of
	// suppressed tids.

	HASH_FIND_INT64(handle->m_suppressed_tids, &tid, stid);

	if(*suppressed && stid == NULL)
	{
		stid = (scap_tid *) malloc(sizeof(scap_tid));
		stid->tid = tid;
		int32_t uth_status = SCAP_SUCCESS;

		HASH_ADD_INT64(handle->m_suppressed_tids, tid, stid);

		if(uth_status != SCAP_SUCCESS)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't add tid to suppressed hash table");
			free(stid);
			return SCAP_FAILURE;
		}
		*suppressed = true;
	}
	else if (!*suppressed && stid != NULL)
	{
		HASH_DEL(handle->m_suppressed_tids, stid);
		free(stid);
		*suppressed = false;
	}

	return SCAP_SUCCESS;
}

int32_t scap_check_suppressed(scap_t *handle, scap_evt *pevent, bool *suppressed)
{
	uint16_t *lens;
	char *valptr;
	uint32_t j;
	int32_t res = SCAP_SUCCESS;
	const char *comm = NULL;
	uint64_t *ptid = NULL;
	scap_tid *stid;

	*suppressed = false;

	// For events that can create a new tid (fork, vfork, clone),
	// we need to check the comm, which might also update the set
	// of suppressed tids.

	switch(pevent->type)
	{
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_EXECVE_19_X:

		lens = (uint16_t *)((char *)pevent + sizeof(struct ppm_evt_hdr));
		valptr = (char *)lens + pevent->nparams * sizeof(uint16_t);

		if(pevent->nparams < 14)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not find process comm in event argument list");
			return SCAP_FAILURE;
		}

		// For all of these events, the comm is argument 14,
		// so we need to walk the list of params that far to
		// find the comm.
		for(j = 0; j < 13; j++)
		{
			if(j == 5)
			{
				ptid = (uint64_t *) valptr;
			}

			valptr += lens[j];
		}

		if(ptid == NULL)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not find ptid in event argument list");
			return SCAP_FAILURE;
		}

		comm = valptr;

		if((res = scap_update_suppressed(handle,
						 comm,
						 pevent->tid, *ptid,
						 suppressed)) != SCAP_SUCCESS)
		{
			// scap_update_suppressed already set handle->m_lasterr on error.
			return res;
		}

		break;

	default:

		HASH_FIND_INT64(handle->m_suppressed_tids, &(pevent->tid), stid);

		// When threads exit they are always removed and no longer suppressed.
		if(pevent->type == PPME_PROCEXIT_1_E)
		{
			if(stid != NULL)
			{
				HASH_DEL(handle->m_suppressed_tids, stid);
				free(stid);
				*suppressed = true;
			}
			else
			{
				*suppressed = false;
			}
		}
		else
		{
			*suppressed = (stid != NULL);
		}

		break;
	}

	return SCAP_SUCCESS;
}
