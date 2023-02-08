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

#include "app.h"
#include "state.h"
#include "signals.h"
#include "actions/actions.h"

bool falco::app::run(int argc, char** argv, bool& restart, std::string& errstr)
{
	falco::app::state s;
    falco::app::run_result res;
    
	if(!s.options.parse(argc, argv, errstr))
	{
		return false;
	}
	for(char **arg = argv; *arg; arg++)
	{
		if(s.cmdline.size() > 0)
		{
			s.cmdline += " ";
		}
		s.cmdline += *arg;
	}

	// The order here is the order in which the methods will be
	// called. Before changing the order, ensure that all
	// dependencies are honored (e.g. don't process events before
	// loading plugins, opening inspector, etc.).
	std::list<std::function<run_result(falco::app::state&)>> run_steps = {
		falco::app::actions::load_config,
		falco::app::actions::print_help,
		falco::app::actions::print_version,
		falco::app::actions::print_page_size,
		falco::app::actions::print_generated_gvisor_config,
		falco::app::actions::print_ignored_events,
		falco::app::actions::print_syscall_events,
		falco::app::actions::require_config_file,
		falco::app::actions::print_plugin_info,
		falco::app::actions::list_plugins,
		falco::app::actions::load_plugins,
		falco::app::actions::init_inspectors,
		falco::app::actions::init_falco_engine,
		falco::app::actions::list_fields,
		falco::app::actions::select_event_sources,
		falco::app::actions::validate_rules_files,
		falco::app::actions::load_rules_files,
		falco::app::actions::print_support,
		falco::app::actions::create_signal_handlers,
		falco::app::actions::attach_inotify_signals,
		falco::app::actions::create_requested_paths,
		falco::app::actions::daemonize,
		falco::app::actions::init_outputs,
		falco::app::actions::init_clients,
		falco::app::actions::configure_syscall_buffer_size,
		falco::app::actions::start_grpc_server,
		falco::app::actions::start_webserver,
		falco::app::actions::process_events,
	};

	std::list<std::function<bool(falco::app::state&, std::string&)>> teardown_steps = {
		falco::app::actions::unregister_signal_handlers,
		falco::app::actions::stop_grpc_server,
		falco::app::actions::stop_webserver,
	};

	for (auto &func : run_steps)
	{
		res = func(s);
		if(!res.proceed)
		{
			break;
		}
	}

	for (auto &func : teardown_steps)
	{
		std::string errstr;

		if(!func(s, errstr))
		{
			// Note only printing warning here--we want all functions
			// to occur even if some return errors.
			fprintf(stderr, "Could not tear down in run(): %s\n", errstr.c_str());
		}
	}

	if(!res.success)
	{
		errstr = res.errstr;
	}

	restart = falco::app::should_restart();

	return res.success;
}
