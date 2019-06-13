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

#include <list>
#include <utility>
#include <string>

#include <yaml-cpp/yaml.h>

#pragma once

// This class parses a K8s Pod Security Policy (psp) and embeds a
// templating engine that can be used with a rules template to result
// in a set of falco rules that detects violations of the psp.

namespace falco
{

class k8s_psp_converter
{
public:
	k8s_psp_converter();
	virtual ~k8s_psp_converter();

	std::string generate_rules(const std::string &psp_yaml, const std::string &rules_template);

private:

	typedef std::list<std::pair<int64_t, int64_t>> ranges_t;

	// Given a yaml node that should be a sequence of objects with
	// min and max properties, populate the provided list of
	// pairs. Throws falco_exception on error.
	void parse_ranges(const YAML::Node &node, ranges_t &ranges);

	void parse_sequence(const YAML::Node &node, std::string &items);

        // Load the provided psp, populating this object with template
        // params. Throws falco_exception on error.
	void load_yaml(const std::string &psp_yaml);

	// The name of this PSP, taken from metadata -> name.
	std::string m_policy_name;

	// The list of images for which this PSP should be considered
	std::list<std::string> m_image_list;

	bool m_allow_privileged;
	bool m_allow_host_pid;
	bool m_allow_host_ipc;
	bool m_allow_host_network;

	std::list<std::pair<int64_t, int64_t>> m_host_network_ports;

	std::string m_allowed_volume_types;

        std::string m_allowed_host_paths;

        std::string m_allowed_flexvolume_drivers;

	std::list<std::pair<int64_t, int64_t>> m_must_run_fs_groups;
	std::list<std::pair<int64_t, int64_t>> m_may_run_fs_groups;

	std::list<std::pair<int64_t, int64_t>> m_must_run_as_users;
	bool m_must_run_as_non_root;

	std::list<std::pair<int64_t, int64_t>> m_must_run_as_groups;
	std::list<std::pair<int64_t, int64_t>> m_may_run_as_groups;

	bool m_read_only_root_filesystem;

	std::list<std::pair<int64_t, int64_t>> m_must_run_supplemental_groups;
	std::list<std::pair<int64_t, int64_t>> m_may_run_supplemental_groups;

	bool m_allow_privilege_escalation;

	std::string m_allowed_capabilities;
	std::string m_allowed_proc_mount_types;
};

};
