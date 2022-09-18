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
#include "stats_writer.h"
#ifndef MINIMAL_BUILD
#include "grpc_server.h"
#include "webserver.h"
#include "indexed_vector.h"
#endif

#include "app_cmdline_options.h"

#include <string>
#include <atomic>

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
	struct state
	{
		// Holds the info mapped for each loaded event source
		struct source_info
		{
			// The index of the given event source in the state's falco_engine,
			// as returned by falco_engine::add_source
			std::size_t engine_idx;
			// The filtercheck list containing all fields compatible
			// with the given event source
			filter_check_list filterchecks;
			// The inspector assigned to this event source. If in capture mode,
			// all event source will share the same inspector. If the event
			// source is a plugin one, the assigned inspector must have that
			// plugin registered in its plugin manager
			std::shared_ptr<sinsp> inspector;
		};

		state();
		virtual ~state();

		std::atomic<bool> restart;
		std::atomic<bool> terminate;

		std::shared_ptr<falco_configuration> config;
		std::shared_ptr<falco_outputs> outputs;
		std::shared_ptr<falco_engine> engine;

		// The set of loaded event sources (by default, the syscall event
		// source plus all event sources coming from the loaded plugins)
		std::set<std::string> loaded_sources;

		// The set of enabled event sources (can be altered by using
		// the --enable-source and --disable-source options)
		std::set<std::string> enabled_sources;

		// Used to load all plugins to get their info. In capture mode,
		// this is also used to open the capture file and read its events
		std::shared_ptr<sinsp> offline_inspector;

		// List of all the information mapped to each event source
		// indexed by event source name
		indexed_vector<source_info> source_infos;

		// List of all plugin configurations indexed by plugin name as returned
		// by their sinsp_plugin::name method
		indexed_vector<falco_configuration::plugin_config> plugin_configs;

		std::string cmdline;

		// Set of syscalls we want the driver to capture
		std::unordered_set<uint32_t> ppm_sc_of_interest;

		// Set of tracepoints we want the driver to capture
		std::unordered_set<uint32_t> tp_of_interest;

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

		// Merges two run results into one
		inline static run_result merge(const run_result& a, const run_result& b)
		{
			auto res = ok();
			res.proceed = a.proceed && b.proceed;
			res.success = a.success && b.success;
			res.errstr = a.errstr;
			if (!b.errstr.empty())
			{
				res.errstr += res.errstr.empty() ? "" : "\n";
				res.errstr += b.errstr;
			}
			return res;
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

	// Convenience method. Read a sequence of filenames and fill
	// in a vector of rules contents.
        // Also fill in the provided rules_contents_t with a mapping from
        // filename (reference) to content (reference).
	// falco_exception if any file could not be read.
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

			std::string rules_content((istreambuf_iterator<char>(is)),
						  istreambuf_iterator<char>());
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

	// These methods comprise the code the application "runs". The
	// order in which the methods run is in application.cpp.
	run_result create_signal_handlers();
	run_result attach_inotify_signals();
	run_result daemonize();
	run_result init_falco_engine();
	run_result init_inspectors();
	run_result init_clients();
	run_result init_outputs();
	run_result list_fields();
	run_result list_plugins();
	run_result load_config();
	run_result load_plugins();
	run_result load_rules_files();
	run_result create_requested_paths();
	run_result print_generated_gvisor_config();
	run_result print_help();
	run_result print_ignored_events();
	run_result print_plugin_info();
	run_result print_support();
	run_result print_syscall_events();
	run_result print_version();
	run_result process_events();
	run_result select_event_sources();
	void configure_interesting_sets();
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
	int create_dir(const std::string &path);
	bool create_handler(int sig, void (*func)(int), run_result &ret);
	void configure_output_format();
	void check_for_ignored_events();
	void format_plugin_info(std::shared_ptr<sinsp_plugin> p, std::ostream& os) const;
	run_result open_offline_inspector();
	run_result open_live_inspector(std::shared_ptr<sinsp> inspector, const std::string& source);
	void add_source_to_engine(const std::string& src);
	void init_syscall_inspector(std::shared_ptr<sinsp> inspector, const falco::app::cmdline_options& opts);
	run_result do_inspect(
		std::shared_ptr<sinsp> inspector,
		const std::string& source, // an empty source represents capture mode
		std::shared_ptr<stats_writer> statsw,
		syscall_evt_drop_mgr &sdropmgr,
		bool check_drops_and_timeouts,
		uint64_t duration_to_tot_ns,
		uint64_t &num_evts);
	void process_inspector_events(
		std::shared_ptr<sinsp> inspector,
		std::shared_ptr<stats_writer> statsw,
		std::string source, // an empty source represents capture mode
		run_result* res) noexcept;

	inline bool is_capture_mode() const 
	{
		return !m_options.trace_filename.empty();
	}

	inline bool is_gvisor_enabled() const
	{
		return !m_options.gvisor_config.empty();
	}

	std::unique_ptr<state> m_state;
	cmdline_options m_options;
	bool m_initialized;
};

}; // namespace app
}; // namespace falco
