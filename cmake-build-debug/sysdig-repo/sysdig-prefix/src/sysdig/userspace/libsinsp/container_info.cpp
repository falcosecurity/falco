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

#include <utility>

#include "container_info.h"
#include "sinsp.h"
#include "sinsp_int.h"

std::vector<std::string> sinsp_container_info::container_health_probe::probe_type_names = {
	"None",
	"Healthcheck",
	"LivenessProbe",
	"ReadinessProbe",
	"End"
};

sinsp_container_info::container_health_probe::container_health_probe()
{
}

sinsp_container_info::container_health_probe::container_health_probe(const probe_type ptype,
								     const std::string &&exe,
								     const std::vector<std::string> &&args)
	: m_probe_type(ptype),
	  m_health_probe_exe(exe),
	  m_health_probe_args(args)
{
}

sinsp_container_info::container_health_probe::~container_health_probe()
{
}

void sinsp_container_info::container_health_probe::parse_health_probes(const Json::Value &config_obj,
								       std::list<container_health_probe> &probes)
{
	// Add any health checks described in the container config/labels.
	for(int i=PT_NONE; i != PT_END; i++)
	{
		string key = probe_type_names[i];
		const Json::Value& probe_obj = config_obj[key];

		if(!probe_obj.isNull() && probe_obj.isObject())
		{
			const Json::Value& probe_exe_obj = probe_obj["exe"];

			if(!probe_exe_obj.isNull() && probe_exe_obj.isConvertibleTo(Json::stringValue))
			{
				const Json::Value& probe_args_obj = probe_obj["args"];

				std::string probe_exe = probe_exe_obj.asString();
				std::vector<std::string> probe_args;

				if(!probe_args_obj.isNull() && probe_args_obj.isArray())
				{
					for(const auto &item : probe_args_obj)
					{
						if(item.isConvertibleTo(Json::stringValue))
						{
							probe_args.push_back(item.asString());
						}
					}
				}
				g_logger.format(sinsp_logger::SEV_DEBUG,
						"add_health_probes: adding %s %s %d",
						probe_type_names[i].c_str(),
						probe_exe.c_str(),
						probe_args.size());

				probes.emplace_back(static_cast<probe_type>(i), std::move(probe_exe), std::move(probe_args));
			}
		}
	}
}

void sinsp_container_info::container_health_probe::add_health_probes(const std::list<container_health_probe> &probes,
								     Json::Value &config_obj)
{
	for(auto &probe : probes)
	{
		string key = probe_type_names[probe.m_probe_type];
		Json::Value args;

		config_obj[key]["exe"] = probe.m_health_probe_exe;
		for(auto &arg : probe.m_health_probe_args)
		{
			args.append(arg);
		}

		config_obj[key]["args"] = args;
	}
}

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_idx(uint32_t idx) const
{
	if (idx >= m_mounts.size())
	{
		return NULL;
	}

	return &(m_mounts[idx]);
}

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_source(std::string &source) const
{
	// note: linear search
	for (auto &mntinfo :m_mounts)
	{
		if(sinsp_utils::glob_match(source.c_str(), mntinfo.m_source.c_str()))
		{
			return &mntinfo;
		}
	}

	return NULL;
}

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_dest(std::string &dest) const
{
	// note: linear search
	for (auto &mntinfo :m_mounts)
	{
		if(sinsp_utils::glob_match(dest.c_str(), mntinfo.m_dest.c_str()))
		{
			return &mntinfo;
		}
	}

	return NULL;
}

std::shared_ptr<sinsp_threadinfo> sinsp_container_info::get_tinfo(sinsp* inspector) const
{
	std::shared_ptr<sinsp_threadinfo> tinfo(inspector->build_threadinfo());
	tinfo->m_tid = -1;
	tinfo->m_pid = -1;
	tinfo->m_vtid = -2;
	tinfo->m_vpid = -2;
	tinfo->m_comm = "container:" + m_id;
	tinfo->m_container_id = m_id;

	return tinfo;
}

sinsp_container_info::container_health_probe::probe_type sinsp_container_info::match_health_probe(sinsp_threadinfo *tinfo) const
{
	g_logger.format(sinsp_logger::SEV_DEBUG,
			"match_health_probe (%s): %u health probes to consider",
			m_id.c_str(), m_health_probes.size());

	auto pred = [&] (const container_health_probe &p) {
                g_logger.format(sinsp_logger::SEV_DEBUG,
				"match_health_probe (%s): Matching tinfo %s %d against %s %d",
				m_id.c_str(),
				tinfo->m_exe.c_str(), tinfo->m_args.size(),
				p.m_health_probe_exe.c_str(), p.m_health_probe_args.size());

                return (p.m_health_probe_exe == tinfo->m_exe &&
			p.m_health_probe_args == tinfo->m_args);
        };

	auto match = std::find_if(m_health_probes.begin(),
				  m_health_probes.end(),
				  pred);

	if(match == m_health_probes.end())
	{
		return container_health_probe::PT_NONE;
	}

	return match->m_probe_type;
}
