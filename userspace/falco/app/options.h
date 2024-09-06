// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <libsinsp/event.h>

#include <string>
#include <vector>
#include <set>
#include <list>

namespace cxxopts { class Options; };

namespace falco {
namespace app {

class options {
public:
	options() = default;
	~options() = default;
	options(options&&) = default;
	options& operator = (options&&) = default;
	options(const options&) = default;
	options& operator = (const options&) = default;

	// Each of these maps directly to a command line option.
	bool help = false;
	bool print_config_schema = false;
	bool print_rule_schema = false;
	std::string conf_filename;
	bool all_events = false;
	sinsp_evt::param_fmt event_buffer_format = sinsp_evt::PF_NORMAL;
	std::vector<std::string> cri_socket_paths;
	bool disable_cri_async = false;
	std::vector<std::string> disable_sources;
	std::vector<std::string> enable_sources;
	std::string gvisor_generate_config_with_socket;
	bool describe_all_rules = false;
	std::string describe_rule;
	bool print_ignored_events;
	bool list_fields = false;
	std::string list_source_fields;
	bool list_plugins = false;
	std::string print_plugin_info;
	bool list_syscall_events = false;
	bool markdown = false;
	int duration_to_tot = 0;
	bool names_only = false;
	std::vector<std::string> cmdline_config_options;
	std::string print_additional;
	std::string pidfilename;
	// Rules list as passed by the user, via cmdline option '-r'
	std::list<std::string> rules_filenames;
	uint64_t snaplen = 0;
	bool print_support = false;
	bool unbuffered_outputs = false;
	std::vector<std::string> validate_rules_filenames;
	bool verbose = false;
	bool print_version_info = false;
	bool print_page_size = false;
	bool dry_run = false;

	bool parse(int argc, char **argv, std::string &errstr);

	const std::string& usage();

private:
	void define(cxxopts::Options& opts);
	std::string m_usage_str;
};

}; // namespace application
}; // namespace falco
