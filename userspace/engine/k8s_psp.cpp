/*
Copyright (C) 2016-2019 Draios Inc dba Sysdig.

This file is part of falco.

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

#include "inja/inja.hpp"

#include "falco_common.h"
#include "k8s_psp.h"

using namespace falco;

k8s_psp_converter::k8s_psp_converter()
	: m_allow_privileged(true),
	  m_allow_host_pid(true),
	  m_allow_host_ipc(true),
	  m_allow_host_network(true),
	  m_must_run_as_non_root(false),
	  m_read_only_root_filesystem(false),
	  m_allow_privilege_escalation(true)
{
}

k8s_psp_converter::~k8s_psp_converter()
{
}

std::string k8s_psp_converter::generate_rules(const std::string &psp_yaml, const std::string &rules_template)
{
	load_yaml(psp_yaml);

	nlohmann::json data;

	data["policy_name"] = m_policy_name;
	data["image_list"] = "[nginx]";
	data["allow_privileged"] = m_allow_privileged;
	data["allow_host_pid"] = m_allow_host_pid;
	data["allow_host_ipc"] = m_allow_host_ipc;
	data["allow_host_network"] = m_allow_host_network;

	data["host_network_ports"] = m_host_network_ports;
	data["allowed_volume_types"] = m_allowed_volume_types;
	data["allowed_flexvolume_drivers"] = m_allowed_flexvolume_drivers;
	data["allowed_host_paths"] = m_allowed_host_paths;

	data["must_run_fs_groups"] = m_must_run_fs_groups;
	data["may_run_fs_groups"] = m_may_run_fs_groups;
	data["must_run_as_users"] = m_must_run_as_users;
	data["must_run_as_non_root"] = m_must_run_as_non_root;
	data["must_run_as_groups"] = m_must_run_as_groups;
	data["may_run_as_groups"] = m_may_run_as_groups;

	data["read_only_root_filesystem"] = m_read_only_root_filesystem;
	data["must_run_supplemental_groups"] = m_must_run_supplemental_groups;
	data["may_run_supplemental_groups"] = m_may_run_supplemental_groups;
	data["allow_privilege_escalation"] = m_allow_privilege_escalation;
	data["allowed_capabilities"] = m_allowed_capabilities;
	data["allowed_proc_mount_types"] = m_allowed_proc_mount_types;

	try {
		return inja::render(rules_template, data);
	}
	catch (const std::runtime_error &ex)
	{
		throw falco_exception(string("Could not render rules template: ") + ex.what());
	}
}

void k8s_psp_converter::parse_ranges(const YAML::Node &node, ranges_t &ranges)
{
	for(auto &range : node)
	{
		m_host_network_ports.push_back(std::make_pair(range["min"].as<int64_t>(),
							      range["max"].as<int64_t>()));
	}
}

void k8s_psp_converter::parse_sequence(const YAML::Node &node, std::string &items)
{
	bool first = true;

	for(auto &item : node)
	{
		if(!first)
		{
			items += ",";
		}
		first = false;
		items += item.as<std::string>();
	}
}

void k8s_psp_converter::load_yaml(const std::string &psp_yaml)
{
	try
	{
		YAML::Node root = YAML::Load(psp_yaml);

		if(!root["kind"] || root["kind"].as<std::string>() != "PodSecurityPolicy")
		{
			throw falco_exception("PSP Yaml Document does not have kind: PodSecurityPolicy");
		}

		if(!root["metadata"])
		{
			throw falco_exception("PSP Yaml Document does not have metadata property");
		}

		auto metadata = root["metadata"];

		if(!metadata["name"])
		{
			throw falco_exception("PSP Yaml Document does not have metadata: name");
		}

		m_policy_name = metadata["name"].as<std::string>();

		if(!root["spec"])
		{
			throw falco_exception("PSP Yaml Document does not have spec property");
		}

		auto spec = root["spec"];

		if(spec["privileged"])
		{
			m_allow_privileged = spec["privileged"].as<bool>();
		}

		if(spec["hostPid"])
		{
			m_allow_host_pid = spec["hostPid"].as<bool>();
		}

		if(spec["hostIPC"])
		{
			m_allow_host_ipc = spec["hostIPC"].as<bool>();
		}

		if(spec["hostNetwork"])
		{
			m_allow_host_network = spec["hostNetwork"].as<bool>();
		}

		if(spec["hostPorts"])
		{
			parse_ranges(spec["hostPorts"], m_host_network_ports);
		}

		if(spec["volumes"])
		{
			parse_sequence(spec["volumes"], m_allowed_volume_types);
		}

		if(spec["allowedHostPaths"])
		{
			bool first = true;
			for(const auto &hostpath : spec["allowedHostPaths"])
			{
				if(!first)
				{
					m_allowed_host_paths += ",";
				}
				first = false;

				// Adding non-wildcard and wildcard versions of path
				m_allowed_host_paths += hostpath["pathPrefix"].as<std::string>();

				m_allowed_host_paths += ",";

				m_allowed_host_paths += hostpath["pathPrefix"].as<std::string>();
				m_allowed_host_paths += "*";
			}
		}

		if(spec["allowedFlexVolumes"])
		{
			bool first = true;
			for(const auto &volume : spec["allowedFlexVolumes"])
			{
				if(!first)
				{
					m_allowed_flexvolume_drivers += ",";
				}
				first = false;

				// Adding non-wildcard and wildcard versions of path
				m_allowed_flexvolume_drivers += volume["driver"].as<std::string>();
			}
		}

		if(spec["fsGroup"])
		{
			std::string rule = spec["fsGroup"]["rule"].as<std::string>();

			if(rule == "MustRunAs")
			{
				parse_ranges(spec["fsGroup"]["ranges"], m_must_run_fs_groups);
			}
			else if(rule == "MayRunAs")
			{
				parse_ranges(spec["fsGroup"]["ranges"], m_may_run_fs_groups);
			}
			else
			{
				throw std::invalid_argument("fsGroup rule \"" + rule + "\" was not one of MustRunAs/MayRunAs");
			}
		}

		if(spec["runAsUser"])
		{
			std::string rule = spec["fsGroup"]["rule"].as<std::string>();

			if(rule == "MustRunAs")
			{
				parse_ranges(spec["fsGroup"]["ranges"], m_must_run_fs_groups);
			}
			else if (rule == "MustRunAsNonRoot")
			{
				m_must_run_as_non_root = true;
			}
		}

		if(spec["runAsGroup"])
		{
			std::string rule = spec["runAsGroup"]["rule"].as<std::string>();

			if(rule == "MustRunAs")
			{
				parse_ranges(spec["runAsGroup"]["ranges"], m_must_run_as_groups);
			}
			else if(rule == "MayRunAs")
			{
				parse_ranges(spec["runAsGroup"]["ranges"], m_may_run_as_groups);
			}
			else
			{
				throw std::invalid_argument("runAsGroup rule \"" + rule + "\" was not one of MustRunAs/MayRunAs");
			}
		}

		if(spec["readOnlyRootFilesystem"])
		{
			m_read_only_root_filesystem = spec["readOnlyRootFilesystem"].as<bool>();
		}

		if(spec["supplementalGroups"])
		{
			std::string rule = spec["supplementalGroups"]["rule"].as<std::string>();

			if(rule == "MustRunAs")
			{
				parse_ranges(spec["supplementalGroups"]["ranges"], m_must_run_as_groups);
			}
			else if(rule == "MayRunAs")
			{
				parse_ranges(spec["supplementalGroups"]["ranges"], m_may_run_as_groups);
			}
			else
			{
				throw std::invalid_argument("supplementalGroups rule \"" + rule + "\" was not one of MustRunAs/MayRunAs");
			}
		}

		if(spec["allowPrivilegeEscalation"])
		{
			m_allow_privilege_escalation = spec["allowPrivilegeEscalation"].as<bool>();
		}

		if(spec["allowedCapabilities"])
		{
			parse_sequence(spec["allowedCapabilities"], m_allowed_capabilities);
		}

		if(spec["allowedProcMountTypes"])
		{
			parse_sequence(spec["allowedProcMountTypes"], m_allowed_proc_mount_types);
		}
	}
	catch (const std::invalid_argument &ex)
	{
		throw falco_exception(string("Could not parse PSP Yaml Document: ") + ex.what());
	}
	catch (const YAML::ParserException& ex)
	{
		throw falco_exception(string("Could not parse PSP Yaml Document: ") + ex.what());
	}
	catch (const YAML::BadConversion& ex)
	{
		throw falco_exception(string("Could not convert value from PSP Yaml Document: ") + ex.what());
	}
}


