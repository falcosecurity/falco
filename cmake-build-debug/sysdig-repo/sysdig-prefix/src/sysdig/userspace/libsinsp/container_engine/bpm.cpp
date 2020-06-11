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
#include "container_engine/bpm.h"
#include "sinsp.h"

using namespace libsinsp::container_engine;

bool bpm::resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info)
{
	sinsp_container_info container_info;
	bool matches = false;

	for(auto it = tinfo->m_cgroups.begin(); it != tinfo->m_cgroups.end(); ++it)
	{
		string cgroup = it->second;
		size_t pos;

		//
		// Non-systemd and systemd BPM
		//
		pos = cgroup.find("bpm-");
		if(pos != string::npos)
		{
			auto id_start = pos + sizeof("bpm-") - 1;
			auto id_end = cgroup.find(".scope", id_start);
			auto id = cgroup.substr(id_start, id_end - id_start);

			// As of BPM v1.0.3, the container ID is only allowed to contain the following chars
			// see https://github.com/cloudfoundry-incubator/bpm-release/blob/v1.0.3/src/bpm/jobid/encoding.go
			if (!id.empty() && strspn(id.c_str(), "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") == id.size())
			{
				container_info.m_type = CT_BPM;
				container_info.m_id = id;
				matches = true;
				break;
			}
		}
	}

	if (!matches)
	{
		return false;
	}

	tinfo->m_container_id = container_info.m_id;
	if(container_cache().should_lookup(container_info.m_id, CT_BPM))
	{
		container_info.m_name = container_info.m_id;
		auto container = std::make_shared<sinsp_container_info>(container_info);
		container_cache().add_container(container, tinfo);
		container_cache().notify_new_container(container_info);
	}
	return true;
}
