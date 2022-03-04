/*
Copyright (C) 2020 The Falco Authors.

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

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <set>
#include <list>
#include <vector>
#include <algorithm>
#include <string>
#include <chrono>
#include <functional>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>

#include <sinsp.h>
#include <filter.h>
#include <eventformatter.h>
#include <plugin.h>

#include "application.h"
#include "logger.h"
#include "utils.h"
#include "fields_info.h"
#include "falco_utils.h"

#include "event_drops.h"
#include "falco_engine.h"
#include "config_falco.h"
#include "statsfilewriter.h"
#ifndef MINIMAL_BUILD
#include "webserver.h"
#endif
#include "banned.h" // This raises a compilation error when certain functions are used

typedef function<void(std::shared_ptr<sinsp> inspector)> open_t;

static std::string syscall_source = "syscall";
static std::string k8s_audit_source = "k8s_audit";

static void display_fatal_err(const string &msg)
{
	falco_logger::log(LOG_ERR, msg);

	/**
	 * If stderr logging is not enabled, also log to stderr. When
	 * daemonized this will simply write to /dev/null.
	 */
	if (! falco_logger::log_stderr)
	{
		std::cerr << msg;
	}
}

#ifndef MINIMAL_BUILD
// Read a jsonl file containing k8s audit events and pass each to the engine.
void read_k8s_audit_trace_file(std::shared_ptr<falco_engine> engine,
			       std::shared_ptr<falco_outputs> outputs,
			       string &trace_filename)
{
	ifstream ifs(trace_filename);

	uint64_t line_num = 0;

	while(ifs)
	{
		string line, errstr;

		getline(ifs, line);
		line_num++;

		if(line == "")
		{
			continue;
		}

		if(!k8s_audit_handler::accept_data(engine, outputs, line, errstr))
		{
			falco_logger::log(LOG_ERR, "Could not read k8s audit event line #" + to_string(line_num) + ", \"" + line + "\": " + errstr + ", stopping");
			return;
		}
	}
}
#endif

//
// Event processing loop
//
uint64_t do_inspect(std::shared_ptr<falco_engine> engine,
		    std::shared_ptr<falco_outputs> outputs,
		    std::shared_ptr<sinsp> inspector,
		    std::string &event_source,
		    std::shared_ptr<falco_configuration> config,
		    syscall_evt_drop_mgr &sdropmgr,
		    uint64_t duration_to_tot_ns,
		    string &stats_filename,
		    uint64_t stats_interval,
		    bool all_events,
		    int &result)
{
	uint64_t num_evts = 0;
	int32_t rc;
	sinsp_evt* ev;
	StatsFileWriter writer;
	uint64_t duration_start = 0;
	uint32_t timeouts_since_last_success_or_msg = 0;

	sdropmgr.init(inspector,
		      outputs,
		      config->m_syscall_evt_drop_actions,
		      config->m_syscall_evt_drop_threshold,
		      config->m_syscall_evt_drop_rate,
		      config->m_syscall_evt_drop_max_burst,
		      config->m_syscall_evt_simulate_drops);

	if (stats_filename != "")
	{
		string errstr;

		if (!writer.init(inspector, stats_filename, stats_interval, errstr))
		{
			throw falco_exception(errstr);
		}
	}

	//
	// Loop through the events
	//
	while(1)
	{

		rc = inspector->next(&ev);

		writer.handle();

		if(falco::app::application::get().state().reopen_outputs)
		{
			outputs->reopen_outputs();
			falco::app::application::get().state().reopen_outputs = false;
		}

		if(falco::app::application::get().state().terminate)
		{
			falco_logger::log(LOG_INFO, "SIGINT received, exiting...\n");
			break;
		}
		else if (falco::app::application::get().state().restart)
		{
			falco_logger::log(LOG_INFO, "SIGHUP received, restarting...\n");
			break;
		}
		else if(rc == SCAP_TIMEOUT)
		{
			if(unlikely(ev == nullptr))
			{
				timeouts_since_last_success_or_msg++;
				if(event_source == syscall_source &&
				   (timeouts_since_last_success_or_msg > config->m_syscall_evt_timeout_max_consecutives))
				{
					std::string rule = "Falco internal: timeouts notification";
					std::string msg = rule + ". " + std::to_string(config->m_syscall_evt_timeout_max_consecutives) + " consecutive timeouts without event.";
					std::string last_event_time_str = "none";
					if(duration_start > 0)
					{
						sinsp_utils::ts_to_string(duration_start, &last_event_time_str, false, true);
					}
					std::map<std::string, std::string> o = {
						{"last_event_time", last_event_time_str},
					};
					auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
					outputs->handle_msg(now, falco_common::PRIORITY_DEBUG, msg, rule, o);
					// Reset the timeouts counter, Falco alerted
					timeouts_since_last_success_or_msg = 0;
				}
			}

			continue;
		}
		else if(rc == SCAP_EOF)
		{
			break;
		}
		else if(rc != SCAP_SUCCESS)
		{
			//
			// Event read error.
			//
			cerr << "rc = " << rc << endl;
			throw sinsp_exception(inspector->getlasterr().c_str());
		}

		// Reset the timeouts counter, Falco succesfully got an event to process
		timeouts_since_last_success_or_msg = 0;
		if(duration_start == 0)
		{
			duration_start = ev->get_ts();
		}
		else if(duration_to_tot_ns > 0)
		{
			if(ev->get_ts() - duration_start >= duration_to_tot_ns)
			{
				break;
			}
		}

		if(!sdropmgr.process_event(inspector, ev))
		{
			result = EXIT_FAILURE;
			break;
		}

		if(!ev->simple_consumer_consider() && !all_events)
		{
			continue;
		}

		// As the inspector has no filter at its level, all
		// events are returned here. Pass them to the falco
		// engine, which will match the event against the set
		// of rules. If a match is found, pass the event to
		// the outputs.
		unique_ptr<falco_engine::rule_result> res = engine->process_event(event_source, ev);
		if(res)
		{
			outputs->handle_event(res->evt, res->rule, res->source, res->priority_num, res->format, res->tags);
		}

		num_evts++;
	}

	return num_evts;
}

//
// ARGUMENT PARSING AND PROGRAM SETUP
//
int falco_init(falco::app::application &app, int argc, char **argv)
{
	int result = EXIT_SUCCESS;
	syscall_evt_drop_mgr sdropmgr;
	bool trace_is_scap = true;
	string outfile;

	// Used for writing trace files
	int duration_seconds = 0;
	int rollover_mb = 0;
	int file_limit = 0;
	unsigned long event_limit = 0L;
	bool compress = false;

	// Used for stats
	double duration;
	scap_stats cstats;

	std::string errstr;
	bool successful = app.init(argc, argv, errstr);

	if(!successful)
	{
		fprintf(stderr, "Runtime error: %s. Exiting.\n", errstr.c_str());
		return EXIT_FAILURE;
	}

	try
	{
		app.run();

		if(app.options().trace_filename.size())
		{
			// Try to open the trace file as a
			// capture file first.
			try {
				app.state().inspector->open(app.options().trace_filename);
				falco_logger::log(LOG_INFO, "Reading system call events from file: " + app.options().trace_filename + "\n");
			}
			catch(sinsp_exception &e)
			{
				falco_logger::log(LOG_DEBUG, "Could not read trace file \"" + app.options().trace_filename + "\": " + string(e.what()));
				trace_is_scap=false;
			}

			if(!trace_is_scap)
			{
#ifdef MINIMAL_BUILD
				// Note that the webserver is not available when MINIMAL_BUILD is defined.
				fprintf(stderr, "Cannot use k8s audit events trace file with a minimal Falco build");
				result = EXIT_FAILURE;
				goto exit;
#else
				try {
					string line;
					nlohmann::json j;

					// Note we only temporarily open the file here.
					// The read file read loop will be later.
					ifstream ifs(app.options().trace_filename);
					getline(ifs, line);
					j = nlohmann::json::parse(line);

					falco_logger::log(LOG_INFO, "Reading k8s audit events from file: " + app.options().trace_filename + "\n");
				}
				catch (nlohmann::json::parse_error& e)
				{
					fprintf(stderr, "Trace filename %s not recognized as system call events or k8s audit events\n", app.options().trace_filename.c_str());
					result = EXIT_FAILURE;
					goto exit;
				}
				catch (exception &e)
				{
					fprintf(stderr, "Could not open trace filename %s for reading: %s\n", app.options().trace_filename.c_str(), e.what());
					result = EXIT_FAILURE;
					goto exit;
				}
#endif
			}
		}
		else
		{
			open_t open_cb = [&app](std::shared_ptr<sinsp> inspector)
			{
				if(app.options().userspace)
				{
					// open_udig() is the underlying method used in the capture code to parse userspace events from the kernel.
					//
					// Falco uses a ptrace(2) based userspace implementation.
					// Regardless of the implementation, the underlying method remains the same.
					inspector->open_udig();
					return;
				}
				inspector->open();
			};
			open_t open_nodriver_cb = [](std::shared_ptr<sinsp> inspector) {
				inspector->open_nodriver();
			};
			open_t open_f;

			// Default mode: both event sources enabled
			if (app.state().enabled_sources.find(syscall_source) != app.state().enabled_sources.end() &&
			    app.state().enabled_sources.find(k8s_audit_source) != app.state().enabled_sources.end())
			{
				open_f = open_cb;
			}
			if (app.state().enabled_sources.find(syscall_source) == app.state().enabled_sources.end())
			{
				open_f = open_nodriver_cb;
			}
			if (app.state().enabled_sources.find(k8s_audit_source) == app.state().enabled_sources.end())
			{
				open_f = open_cb;
			}

			try
			{
				open_f(app.state().inspector);
			}
			catch(sinsp_exception &e)
			{
				// If syscall input source is enabled and not through userspace instrumentation
				if (app.state().enabled_sources.find(syscall_source) != app.state().enabled_sources.end() && !app.options().userspace)
				{
					// Try to insert the Falco kernel module
					if(system("modprobe " DRIVER_NAME " > /dev/null 2> /dev/null"))
					{
						falco_logger::log(LOG_ERR, "Unable to load the driver.\n");
					}
					open_f(app.state().inspector);
				}
				else
				{
					rethrow_exception(current_exception());
				}
			}
		}

		// This must be done after the open
		if(!app.options().all_events)
		{
			app.state().inspector->start_dropping_mode(1);
		}

		if(outfile != "")
		{
			app.state().inspector->setup_cycle_writer(outfile, rollover_mb, duration_seconds, file_limit, event_limit, compress);
			app.state().inspector->autodump_next_file();
		}

		duration = ((double)clock()) / CLOCKS_PER_SEC;

#ifndef MINIMAL_BUILD

		falco_logger::log(LOG_DEBUG, "Setting metadata download max size to " + to_string(app.state().config->m_metadata_download_max_mb) + " MB\n");
		falco_logger::log(LOG_DEBUG, "Setting metadata download chunk wait time to " + to_string(app.state().config->m_metadata_download_chunk_wait_us) + " μs\n");
		falco_logger::log(LOG_DEBUG, "Setting metadata download watch frequency to " + to_string(app.state().config->m_metadata_download_watch_freq_sec) + " seconds\n");
		app.state().inspector->set_metadata_download_params(app.state().config->m_metadata_download_max_mb * 1024 * 1024, app.state().config->m_metadata_download_chunk_wait_us, app.state().config->m_metadata_download_watch_freq_sec);


#endif

		if(!app.options().trace_filename.empty() && !trace_is_scap)
		{
#ifndef MINIMAL_BUILD
			read_k8s_audit_trace_file(app.state().engine,
						  app.state().outputs,
						  app.options().trace_filename);
#endif
		}
		else
		{
			uint64_t num_evts;

			num_evts = do_inspect(app.state().engine,
					      app.state().outputs,
					      app.state().inspector,
					      app.state().event_source,
					      app.state().config,
					      sdropmgr,
					      uint64_t(app.options().duration_to_tot*ONE_SECOND_IN_NS),
					      app.options().stats_filename,
					      app.options().stats_interval,
					      app.options().all_events,
					      result);

			duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

			app.state().inspector->get_capture_stats(&cstats);

			if(app.options().verbose)
			{
				fprintf(stderr, "Driver Events:%" PRIu64 "\nDriver Drops:%" PRIu64 "\n",
					cstats.n_evts,
					cstats.n_drops);

				fprintf(stderr, "Elapsed time: %.3lf, Captured Events: %" PRIu64 ", %.2lf eps\n",
					duration,
					num_evts,
					num_evts / duration);
			}

		}

		// Honor -M also when using a trace file.
		// Since inspection stops as soon as all events have been consumed
		// just await the given duration is reached, if needed.
		if(!app.options().trace_filename.empty() && app.options().duration_to_tot>0)
		{
			std::this_thread::sleep_for(std::chrono::seconds(app.options().duration_to_tot));
		}

		app.state().inspector->close();
		app.state().engine->print_stats();
		sdropmgr.print_stats();
	}
	catch(exception &e)
	{
		display_fatal_err("Runtime error: " + string(e.what()) + ". Exiting.\n");

		result = EXIT_FAILURE;
	}

exit:

	return result;
}

//
// MAIN
//
int main(int argc, char **argv)
{
	int rc;
	falco::app::application &app = falco::app::application::get();

	// m_restart will cause the falco loop to exit, but we
	// should reload everything and start over.
	while((rc = falco_init(app, argc, argv)) == EXIT_SUCCESS && app.state().restart)
	{
		app.state().restart = false;
	}

	return rc;
}
