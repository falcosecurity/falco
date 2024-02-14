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
	options();
	virtual ~options();
	options(options&&) = default;
	options& operator = (options&&) = default;
	options(const options&) = default;
	options& operator = (const options&) = default;

	// Each of these maps directly to a command line option.
	bool help;
	std::string conf_filename;
	bool all_events;
	sinsp_evt::param_fmt event_buffer_format;
	std::vector<std::string> cri_socket_paths;
	bool disable_cri_async;
	std::vector<std::string> disable_sources;
	std::vector<std::string> disabled_rule_substrings;
	std::vector<std::string> enable_sources;
	std::string gvisor_generate_config_with_socket;
	bool describe_all_rules;
	std::string describe_rule;
	bool print_ignored_events;
	bool list_fields;
	std::string list_source_fields;
	bool list_plugins;
	std::string print_plugin_info;
	bool list_syscall_events;
	bool markdown;
	int duration_to_tot;
	bool names_only;
	std::vector<std::string> cmdline_config_options;
	std::string print_additional;
	std::string pidfilename;
	// Rules list as passed by the user, via cmdline option '-r'
	std::list<std::string> rules_filenames;
	uint64_t snaplen;
	bool print_support;
	std::set<std::string> disabled_rule_tags;
	std::set<std::string> enabled_rule_tags;
	bool unbuffered_outputs;
	std::vector<std::string> validate_rules_filenames;
	bool verbose;
	bool print_version_info;
	bool print_page_size;
	bool dry_run;

	bool parse(int argc, char **argv, std::string &errstr);

	const std::string& usage();

private:
	void define(cxxopts::Options& opts);
	std::string m_usage_str;
};

}; // namespace application
}; // namespace falco
