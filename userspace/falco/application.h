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

// The falco "app" will eventually replace the monolithic code in
// falco.cpp. We expect it will be responsible for the following:
//  - Parsing/validating command line options
//  - Parsing/validating falco config
//  - Initialize prerequisites (inspector, falco engine, webserver, etc)
//  - Loading plugins
//  - Loading/validating rules
//  - Command/subcommand execution (e.g. --list/--list-fields, or
//    nothing specified to run "main" loop)

// For now, it is only responsible for command line options.
#pragma once

#include "configuration.h"

#include "app_cmdline_options.h"
#include "app_action_manager.h"

#include <string>

namespace falco {
namespace app {

class application {
public:
	class action_state {
	public:
		action_state();
		virtual ~action_state();

		bool restart;
		bool terminate;
		bool reopen_outputs;

		std::shared_ptr<falco_configuration> config;
		std::shared_ptr<falco_outputs> outputs;
		std::shared_ptr<falco_engine> engine;
		std::shared_ptr<sinsp> inspector;
		std::set<std::string> enabled_sources;

		// The event source is syscall by default. If an input
		// plugin was found, the source is the source of that
		// plugin.
		std::string event_source;

		std::list<sinsp_plugin::info> plugin_infos;

		std::map<string,uint64_t> required_engine_versions;

		std::string cmdline;

		bool trace_is_scap;
	};

	static std::string s_syscall_source;
	static std::string s_k8s_audit_source;

	application();
	virtual ~application();

	// Singleton for application
	static application &get();

	cmdline_options &options();
	action_state &state();

	bool init(int argc, char **argv, std::string &errstr);

	runnable_action::run_result run();

private:
	std::shared_ptr<action_state> m_state;
	std::shared_ptr<action_manager> m_action_manager;
	cmdline_options m_cmdline_options;
	bool m_initialized;
};

}; // namespace app
}; // namespace falco
