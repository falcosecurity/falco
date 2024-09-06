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

#include "app.h"
#include "state.h"
#include "signals.h"
#include "actions/actions.h"

falco::atomic_signal_handler falco::app::g_terminate_signal;
falco::atomic_signal_handler falco::app::g_restart_signal;
falco::atomic_signal_handler falco::app::g_reopen_outputs_signal;

using app_action = std::function<falco::app::run_result(falco::app::state&)>;

libsinsp::events::set<ppm_sc_code> falco::app::ignored_sc_set()
{
	// we ignore all the I/O syscalls that can have very high throughput and
	// that can badly impact performance. Of those, we avoid ignoring the
	// ones that are part of the base set used by libsinsp for maintaining
	// its internal state.
	return libsinsp::events::io_sc_set().diff(libsinsp::events::sinsp_state_sc_set());
}

bool falco::app::run(int argc, char** argv, bool& restart, std::string& errstr)
{
	falco::app::state s;    
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
	return falco::app::run(s, restart, errstr);
}

bool falco::app::run(falco::app::state& s, bool& restart, std::string& errstr)
{
	// The order here is the order in which the methods will be
	// called. Before changing the order, ensure that all
	// dependencies are honored (e.g. don't process events before
	// loading plugins, opening inspector, etc.).
	std::list<app_action> run_steps = {
		falco::app::actions::print_config_schema,
		falco::app::actions::print_rule_schema,
		falco::app::actions::load_config,
		falco::app::actions::print_help,
		falco::app::actions::print_kernel_version,
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
		falco::app::actions::init_outputs,
		falco::app::actions::create_signal_handlers,
		falco::app::actions::create_requested_paths,
		falco::app::actions::pidfile,
		falco::app::actions::configure_interesting_sets,
		falco::app::actions::configure_syscall_buffer_size,
		falco::app::actions::configure_syscall_buffer_num,
		falco::app::actions::start_grpc_server,
		falco::app::actions::start_webserver,
		falco::app::actions::process_events,
	};

	std::list<app_action> teardown_steps = {
		falco::app::actions::unregister_signal_handlers,
		falco::app::actions::stop_grpc_server,
		falco::app::actions::stop_webserver,
		falco::app::actions::close_inspectors,
	};

	falco::app::run_result res = falco::app::run_result::ok();
	for (const auto &func : run_steps)
	{
		res = falco::app::run_result::merge(res, func(s));
		if(!res.proceed)
		{
			break;
		}
	}

	for (const auto &func : teardown_steps)
	{
		res = falco::app::run_result::merge(res, func(s));
		// note: we always proceed because we don't want to miss teardown steps
	}

	if(!res.success)
	{
		errstr = res.errstr;
	}

	restart = s.restart;

	return res.success;
}
