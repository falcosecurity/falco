/*
Copyright (C) 2022 The Falco Authors.

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

#pragma once

#include <event.h>

#include <cxxopts.hpp>

#include <string>
#include <vector>
#include <set>

namespace falco {
namespace app {

class cmdline_options {
public:
	cmdline_options();
	~cmdline_options();

	// Each of these maps directly to a command line option.
	bool help;
	std::string conf_filename;
	bool all_events;
	sinsp_evt::param_fmt event_buffer_format;
	std::vector<std::string> cri_socket_paths;
	bool daemon;
	bool disable_cri_async;
	std::vector<std::string> disable_sources;
	std::vector<std::string> disabled_rule_substrings;
	std::string trace_filename;
	std::string gvisor_config;
	std::string gvisor_generate_config_with_socket;
	std::string gvisor_root;
	std::string k8s_api;
	std::string k8s_api_cert;
	std::string k8s_node_name;
	bool describe_all_rules;
	std::string describe_rule;
	bool print_ignored_events;
	bool list_fields;
	std::string list_source_fields;
	bool list_plugins;
	std::string print_plugin_info;
	bool list_syscall_events;
	bool markdown;
	std::string mesos_api;
	int duration_to_tot;
	bool names_only;
	std::vector<std::string> cmdline_config_options;
	std::string print_additional;
	std::string pidfilename;
	// Rules list as passed by the user, via cmdline option '-r'
	std::list<std::string> rules_filenames;
	std::string stats_filename;
	uint64_t stats_interval;
	uint64_t snaplen;
	bool print_support;
	std::set<std::string> disabled_rule_tags;
	std::set<std::string> enabled_rule_tags;
	bool unbuffered_outputs;
	bool userspace;
	std::vector<std::string> validate_rules_filenames;
	bool verbose;
	bool print_version_info;
	bool modern_bpf;

	bool parse(int argc, char **argv, std::string &errstr);

	std::string usage();
private:
	void define();

	cxxopts::Options m_cmdline_opts;
	cxxopts::ParseResult m_cmdline_parsed;
};

}; // namespace application
}; // namespace falco
