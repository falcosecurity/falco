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

static inline bool should_take_action_to_signal(std::atomic<int>& v)
{
	// we expected the signal to be received, and we try to set action-taken flag
	int value = APP_SIGNAL_SET;
	while (!v.compare_exchange_weak(
			value,
			APP_SIGNAL_ACTION_TAKEN,
			std::memory_order_seq_cst,
			std::memory_order_seq_cst))
	{
		// application already took action, there's no need to do it twice
		if (value == APP_SIGNAL_ACTION_TAKEN)
		{
			return false;
		}

		// signal did was not really received, so we "fake" receiving it
		if (value == APP_SIGNAL_NOT_SET)
		{
			v.store(APP_SIGNAL_SET, std::memory_order_seq_cst);
		}

		// reset "expected" CAS variable and keep looping until we succeed
		value = APP_SIGNAL_SET;
	}
	return true;
}

namespace falco {
namespace app {

std::atomic<int> g_terminate(APP_SIGNAL_NOT_SET);
std::atomic<int> g_restart(APP_SIGNAL_NOT_SET);
std::atomic<int> g_reopen_outputs(APP_SIGNAL_NOT_SET);

application::run_result::run_result()
	: success(true), errstr(""), proceed(true)
{
}

application::run_result::~run_result()
{
}

application::state::state()
	: loaded_sources(),
	  enabled_sources(),
	  source_infos(),
	  plugin_configs(),
	  ppm_sc_of_interest(),
	  tp_of_interest(),
	  syscall_buffer_bytes_size(DEFAULT_DRIVER_BUFFER_BYTES_DIM)
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
	if (should_take_action_to_signal(falco::app::g_terminate))
	{
		falco_logger::log(LOG_INFO, "SIGINT received, exiting...\n");
	}
}

void application::reopen_outputs()
{
	if (should_take_action_to_signal(falco::app::g_reopen_outputs))
	{
		falco_logger::log(LOG_INFO, "SIGUSR1 received, reopening outputs...\n");
		if(m_state != nullptr && m_state->outputs != nullptr)
		{
			m_state->outputs->reopen_outputs();
		}
	}
}

void application::restart()
{
	if (should_take_action_to_signal(falco::app::g_restart))
	{
		falco_logger::log(LOG_INFO, "SIGHUP received, restarting...\n");
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
		std::bind(&application::print_page_size, this),
		std::bind(&application::print_generated_gvisor_config, this),
		std::bind(&application::print_ignored_events, this),
		std::bind(&application::print_syscall_events, this),
		std::bind(&application::load_config, this),
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
		std::bind(&application::create_signal_handlers, this),
		std::bind(&application::attach_inotify_signals, this),
		std::bind(&application::create_requested_paths, this),
		std::bind(&application::daemonize, this),
		std::bind(&application::init_outputs, this),
		std::bind(&application::init_clients, this),
		std::bind(&application::configure_syscall_buffer_size, this),
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

	restart = should_restart();

	return res.success;
}

}; // namespace app
}; // namespace falco
