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

#include "../state.h"
#include "../run_result.h"

namespace falco {
namespace app {
namespace actions {

falco::app::run_result create_signal_handlers(falco::app::state& s);
falco::app::run_result attach_inotify_signals(falco::app::state& s);
falco::app::run_result daemonize(falco::app::state& s);
falco::app::run_result init_falco_engine(falco::app::state& s);
falco::app::run_result init_inspectors(falco::app::state& s);
falco::app::run_result init_clients(falco::app::state& s);
falco::app::run_result init_outputs(falco::app::state& s);
falco::app::run_result list_fields(falco::app::state& s);
falco::app::run_result list_plugins(falco::app::state& s);
falco::app::run_result load_config(falco::app::state& s);
falco::app::run_result require_config_file(falco::app::state& s);
falco::app::run_result load_plugins(falco::app::state& s);
falco::app::run_result load_rules_files(falco::app::state& s);
falco::app::run_result create_requested_paths(falco::app::state& s);
falco::app::run_result print_generated_gvisor_config(falco::app::state& s);
falco::app::run_result print_help(falco::app::state& s);
falco::app::run_result print_ignored_events(falco::app::state& s);
falco::app::run_result print_plugin_info(falco::app::state& s);
falco::app::run_result print_support(falco::app::state& s);
falco::app::run_result print_syscall_events(falco::app::state& s);
falco::app::run_result print_version(falco::app::state& s);
falco::app::run_result print_page_size(falco::app::state& s);
falco::app::run_result process_events(falco::app::state& s);
falco::app::run_result select_event_sources(falco::app::state& s);
falco::app::run_result configure_syscall_buffer_size(falco::app::state& s);
falco::app::run_result start_grpc_server(falco::app::state& s);
falco::app::run_result start_webserver(falco::app::state& s);
falco::app::run_result validate_rules_files(falco::app::state& s);

// teardown
bool unregister_signal_handlers(falco::app::state& s, std::string &errstr);
bool stop_grpc_server(falco::app::state& s, std::string &errstr);
bool stop_webserver(falco::app::state& s, std::string &errstr);

// helpers
bool check_rules_plugin_requirements(falco::app::state& s, std::string& err);
falco::app::run_result open_offline_inspector(falco::app::state& s);
void print_enabled_event_sources(falco::app::state& s);
void configure_interesting_sets(falco::app::state& s);
void format_plugin_info(std::shared_ptr<sinsp_plugin> p, std::ostream& os);
falco::app::run_result open_live_inspector(
    falco::app::state& s,
    std::shared_ptr<sinsp> inspector,
    const std::string& source);

template<class InputIterator>
void read_files(InputIterator begin, InputIterator end,
		std::vector<std::string>& rules_contents,
		falco::load_result::rules_contents_t& rc)
{
	// Read the contents in a first pass
	for(auto it = begin; it != end; it++)
	{
		std::string &filename = *it;
		std::ifstream is;
		is.open(filename);
		if (!is.is_open())
		{
			throw falco_exception("Could not open file " + filename + " for reading");
		}

		std::string rules_content((std::istreambuf_iterator<char>(is)),
						std::istreambuf_iterator<char>());
		rules_contents.emplace_back(std::move(rules_content));
	}

	// Populate the map in a second pass to avoid
	// references becoming invalid.
	auto it = begin;
	auto rit = rules_contents.begin();
	for(; it != end && rit != rules_contents.end(); it++, rit++)
	{
		rc.emplace(*it, *rit);
	}

	// Both it and rit must be at the end, otherwise
	// there's a bug in the above
	if(it != end || rit != rules_contents.end())
	{
		throw falco_exception("Unexpected mismatch in rules content name/rules content sets?");
	}
}

}; // namespace actions
}; // namespace app
}; // namespace falco
