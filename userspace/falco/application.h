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

#include "configuration.h"
#ifndef MINIMAL_BUILD
#include "grpc_server.h"
#include "webserver.h"
#endif

#include "app_cmdline_options.h"

#include <string>

namespace falco {
namespace app {

class application {
public:
	application();
	virtual ~application();

	// These are only used in signal handlers. Other than there,
	// the control flow of the application should not be changed
	// from the outside.
	void terminate();
	void reopen_outputs();
	void restart();

	bool init(int argc, char **argv, std::string &errstr);

	// Returns whether the application completed with errors or
	// not. errstr will contain details when run() returns false.
	//
	// If restart (generally set by signal handlers) is
	// true, the application should be restarted instead of
	// exiting.
	bool run(std::string &errstr, bool &restart);

private:
	// Holds the state used and shared by the below methods that
	// actually implement the application. Declared as a
	// standalone class to allow for a bit of separation between
	// application state and instance variables, and to also defer
	// initializing this state until application::init.
	struct state {
		state();
		virtual ~state();

		bool restart;
		bool terminate;
		bool reopen_outputs;

		std::shared_ptr<falco_configuration> config;
		std::shared_ptr<falco_outputs> outputs;
		std::shared_ptr<falco_engine> engine;
		std::shared_ptr<sinsp> inspector;
		std::set<std::string> enabled_sources;

		// The event source index that correspond to "syscall"
		std::size_t syscall_source_idx;

		// All filterchecks created by plugins go in this
		// list. If we ever support multiple event sources at
		// the same time, this, and the factories created in
		// init_inspector/load_plugins, will have to be a map
		// from event source to filtercheck list.
		std::map<std::string, filter_check_list> plugin_filter_checks;

		std::map<string,uint64_t> required_engine_versions;

		std::string cmdline;

#ifndef MINIMAL_BUILD
		falco::grpc::server grpc_server;
		std::thread grpc_server_thread;

		falco_webserver webserver;
#endif
	};

	// Used in the below methods to indicate how to proceed.
	struct run_result {
		// Successful result
		inline static run_result ok()
		{
			run_result r;
			r.success = true;
			r.errstr = "";
			r.proceed = true;
			return r;
		}

		// Successful result that causes the program to stop
		inline static run_result exit()
		{
			run_result r = ok();
			r.proceed = false;
			return r;
		}

		// Failure result that causes the program to stop with an error
		inline static run_result fatal(std::string err)
		{
			run_result r;
			r.success = false;
			r.errstr = err;
			r.proceed = false;
			return r;
		}

		run_result();
		virtual ~run_result();

		// If true, the method completed successfully.
		bool success;
		// If success==false, details on the error.
		std::string errstr;
		// If true, subsequent methods should be performed. If
		// false, subsequent methods should *not* be performed
		// and falco should tear down/exit/restart.
		bool proceed;
	};

	// These methods comprise the code the application "runs". The
	// order in which the methods run is in application.cpp.
	run_result create_signal_handlers();
	run_result attach_inotify_signals();
 	run_result daemonize();
 	run_result init_falco_engine();
 	run_result init_inspector();
 	run_result init_outputs();
 	run_result list_fields();
 	run_result list_plugins();
 	run_result load_config();
 	run_result load_plugins();
 	run_result load_rules_files();
 	run_result open_inspector();
 	run_result print_help();
	run_result print_ignored_events();
 	run_result print_support();
 	run_result print_version();
 	run_result process_events();
#ifndef MINIMAL_BUILD
 	run_result start_grpc_server();
 	run_result start_webserver();
#endif
 	run_result validate_rules_files();

	// These methods comprise application teardown. The order in
	// which the methods run is in application.cpp.
	bool close_inspector(std::string &errstr);
	bool unregister_signal_handlers(std::string &errstr);
#ifndef MINIMAL_BUILD
	bool stop_grpc_server(std::string &errstr);
	bool stop_webserver(std::string &errstr);
#endif

	// Methods called by the above methods
	bool create_handler(int sig, void (*func)(int), run_result &ret);
	void configure_output_format();
	void check_for_ignored_events();
	void print_all_ignored_events();
	run_result do_inspect(syscall_evt_drop_mgr &sdropmgr,
			    uint64_t duration_to_tot_ns,
			    uint64_t &num_events);
	
	inline bool is_syscall_source_enabled() const 
	{
		return m_state->enabled_sources.find(falco_common::syscall_source)
			!= m_state->enabled_sources.end();
	}

	inline bool is_capture_mode() const 
	{
		return !m_options.trace_filename.empty();
	}

	std::unique_ptr<state> m_state;
	cmdline_options m_options;
	bool m_initialized;
};

}; // namespace app
}; // namespace falco
