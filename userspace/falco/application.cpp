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

// The falco "app" holds application-level configuration and contains
// the implementation of any subcommand-like behaviors like --list, -i
// (print_ignored_events), etc.

// It also contains the code to initialize components like the
// inspector, falco engine, etc.

#include "application.h"
#include "falco_common.h"

using namespace std::placeholders;

namespace falco {
namespace app {

application::run_result::run_result()
	: success(true), errstr(""), proceed(true)
{
}

application::run_result::~run_result()
{
}

application::state::state()
	: restart(false),
	  terminate(false),
	  loaded_sources(),
	  enabled_sources(),
	  source_infos(),
	  plugin_configs(),
	  ppm_sc_of_interest(),
	  tp_of_interest()
{
	config = std::make_shared<falco_configuration>();
	engine = std::make_shared<falco_engine>();
	offline_inspector = std::make_shared<sinsp>();
	outputs = nullptr;
}

application::state::~state()
{
}

application::application()
	: m_initialized(false)
{
}

application::~application()
{
}

void application::terminate()
{
	if(m_state != nullptr)
	{
		m_state->terminate.store(true, std::memory_order_seq_cst);
	}
}

void application::reopen_outputs()
{
	if(m_state != nullptr && m_state->outputs != nullptr)
	{
		// note: it is ok to do this inside the signal handler because
		// in the current falco_outputs implementation this is non-blocking
		m_state->outputs->reopen_outputs();
	}
}

void application::restart()
{
	if(m_state != nullptr)
	{
		m_state->restart.store(true, std::memory_order_seq_cst);
	}
}

bool application::init(int argc, char **argv, std::string &errstr)
{
	if(m_initialized)
	{
		throw falco_exception("Application already initialized");
	}

	m_state.reset(new state());

	if(!m_options.parse(argc, argv, errstr))
	{
		return false;
	}

	for(char **arg = argv; *arg; arg++)
	{
		if(m_state->cmdline.size() > 0)
		{
			m_state->cmdline += " ";
		}
		m_state->cmdline += *arg;
	}

	m_initialized = true;
	return true;
}

bool application::run(std::string &errstr, bool &restart)
{
	run_result res;

	// The order here is the order in which the methods will be
	// called. Before changing the order, ensure that all
	// dependencies are honored (e.g. don't process events before
	// loading plugins, opening inspector, etc.).
	std::list<std::function<run_result()>> run_steps = {
		std::bind(&application::print_help, this),
		std::bind(&application::print_version, this),
		std::bind(&application::print_generated_gvisor_config, this),
		std::bind(&application::print_ignored_events, this),
		std::bind(&application::print_syscall_events, this),
		std::bind(&application::load_config, this),
		std::bind(&application::create_signal_handlers, this),
		std::bind(&application::print_plugin_info, this),
		std::bind(&application::list_plugins, this),
		std::bind(&application::load_plugins, this),
		std::bind(&application::init_inspectors, this),
		std::bind(&application::init_falco_engine, this),
		std::bind(&application::list_fields, this),
		std::bind(&application::select_event_sources, this),
		std::bind(&application::validate_rules_files, this),
		std::bind(&application::load_rules_files, this),
		std::bind(&application::print_support, this),
		std::bind(&application::attach_inotify_signals, this),
		std::bind(&application::create_requested_paths, this),
		std::bind(&application::daemonize, this),
		std::bind(&application::init_outputs, this),
		std::bind(&application::init_clients, this),
#ifndef MINIMAL_BUILD
		std::bind(&application::start_grpc_server, this),
		std::bind(&application::start_webserver, this),
#endif
		std::bind(&application::process_events, this)
	};

	std::list<std::function<bool(std::string &)>> teardown_steps = {
		std::bind(&application::unregister_signal_handlers, this, _1),
#ifndef MINIMAL_BUILD
		std::bind(&application::stop_grpc_server, this, _1),
		std::bind(&application::stop_webserver, this, _1)
#endif
	};

	for (auto &func : run_steps)
	{
		res = func();

		if(!res.proceed)
		{
			break;
		}
	}

	for (auto &func : teardown_steps)
	{
		std::string errstr;

		if(!func(errstr))
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

	restart = m_state->restart;

	return res.success;
}

}; // namespace app
}; // namespace falco
