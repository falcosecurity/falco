/*
Copyright (C) 2013-2019 Draios Inc dba Sysdig.

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

#include "container_engine/mesos.h"

#include <unistd.h>

#include "sinsp.h"
#include "sinsp_int.h"

bool libsinsp::container_engine::mesos::match(sinsp_threadinfo* tinfo, sinsp_container_info &container_info)
{
	for(auto it = tinfo->m_cgroups.begin(); it != tinfo->m_cgroups.end(); ++it)
	{
		string cgroup = it->second;
		size_t pos;

		pos = cgroup.find("/mesos/");
		if(pos != string::npos)
		{
			// It should match `/mesos/a9f41620-b165-4d24-abe0-af0af92e7b20`
			auto id = cgroup.substr(pos + sizeof("/mesos/") - 1);
			if(id.size() == 36 && id.find_first_not_of("0123456789abcdefABCDEF-") == string::npos)
			{
				container_info.m_type = CT_MESOS;
				container_info.m_id = move(id);
				// Consider a mesos container valid only if we find the mesos_task_id
				// this will exclude from the container itself the mesos-executor
				// but makes sure that we have task_id parsed properly. Otherwise what happens
				// is that we'll create a mesos container struct without a mesos_task_id
				// and for all other processes we'll use it
				return set_mesos_task_id(container_info, tinfo);
			}
		}
	}
	return false;
}

bool libsinsp::container_engine::mesos::resolve(sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	auto container = std::make_shared<sinsp_container_info>();

	if (!match(tinfo, *container))
		return false;

	tinfo->m_container_id = container->m_id;
	if(container_cache().should_lookup(container->m_id, CT_MESOS))
	{
		container->m_name = container->m_id;
		container_cache().add_container(container, tinfo);
		container_cache().notify_new_container(*container);
	}
	return true;
}

string libsinsp::container_engine::mesos::get_env_mesos_task_id(sinsp_threadinfo* tinfo)
{
	string mtid;

	sinsp_threadinfo::visitor_func_t visitor = [&mtid] (sinsp_threadinfo *ptinfo)
	{
		// Mesos task ID detection is not a straightforward task;
		// this list may have to be extended.
		mtid = ptinfo->get_env("MESOS_TASK_ID"); // Marathon
		if(!mtid.empty()) { return false; }
		mtid = ptinfo->get_env("mesos_task_id"); // Chronos
		if(!mtid.empty()) { return false; }
		mtid = ptinfo->get_env("MESOS_EXECUTOR_ID"); // others
		if(!mtid.empty()) { return false; }

		return true;
	};

	// Try the current thread first. visitor returns true if mtid
	// was not filled in. In this case we should traverse the
	// parents.
	if(tinfo && visitor(tinfo))
	{
		tinfo->traverse_parent_state(visitor);
	}

	return mtid;
}

bool libsinsp::container_engine::mesos::set_mesos_task_id(sinsp_container_info &container, sinsp_threadinfo* tinfo)
{
	ASSERT(tinfo);

	// there are applications that do not share their environment in /proc/[PID]/environ
	// since we need MESOS_TASK_ID environment variable to discover Mesos containers,
	// there is a workaround for such cases:
	// - for docker containers, we discover it directly from container, through Remote API
	//   (see sinsp_container_manager::parse_docker() for details)
	// - for mesos native containers, parent process has the MESOS_TASK_ID (or equivalent, see
	//   get_env_mesos_task_id(sinsp_threadinfo*) implementation) environment variable, so we
	//   peek into the parent process environment to discover it

	if(tinfo)
	{
		string& mtid = container.m_mesos_task_id;
		if(mtid.empty())
		{
			mtid = get_env_mesos_task_id(tinfo);

			// Ensure that the mesos task id vaguely looks
			// like a real id. We assume it must be at
			// least 3 characters and contain a dot or underscore
			if(!mtid.empty() && mtid.length()>=3 &&
			   (mtid.find_first_of("._") != std::string::npos))
			{
				g_logger.log("Mesos native container: [" + container.m_id + "], Mesos task ID: " + mtid, sinsp_logger::SEV_DEBUG);
				return true;
			}
			else
			{
				g_logger.log("Mesos container [" + container.m_id + "],"
										     "thread [" + std::to_string(tinfo->m_tid) +
					     "], has likely malformed mesos task id [" + mtid + "], ignoring", sinsp_logger::SEV_DEBUG);
			}
		}
	}
	return false;
}

