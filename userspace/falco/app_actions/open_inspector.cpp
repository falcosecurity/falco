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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "application.h"

using namespace falco::app;

#define FALCO_BPF_ENV_VARIABLE "FALCO_BPF_PROBE"
#define MAX_PROBE_PATH_SIZE 4096

typedef std::function<void(std::shared_ptr<sinsp> inspector)> open_t;

application::run_result application::open_inspector()
{
	// Notify engine that we finished loading and enabling all rules
	m_state->engine->complete_rule_loading();

	/// TODO: in a future change we can unify how we open different engines...
	/// today we use: flags, env variables, configuration files...
	if(is_capture_mode()) /* Savefile engine. */
	{
		// Try to open the trace file as a
		// capture file first.
		try
		{
			m_state->inspector->open_savefile(m_options.trace_filename, 0);
			falco_logger::log(LOG_INFO, "Reading system call events from file: " + m_options.trace_filename + "\n");
		}
		catch(sinsp_exception &e)
		{
			return run_result::fatal("Cannot open trace filename " + m_options.trace_filename + " for reading: " + e.what());
		}
	}
	else if(m_state->m_plugin_name != "") /* plugin engine. */
	{
		try
		{
			m_state->inspector->open_plugin(m_state->m_plugin_name, m_state->m_plugin_open_params);
			falco_logger::log(LOG_INFO, "Starting capture with plugin: " + m_state->m_plugin_name + "\n");
		}
		catch(sinsp_exception &e)
		{
			return run_result::fatal("Cannot use '" + m_state->m_plugin_name + "' plugin: " + e.what());
		}
	}
	else if(m_options.userspace) /* udig engine. */
	{
		// open_udig() is the underlying method used in the capture code to parse userspace events from the kernel.
		//
		// Falco uses a ptrace(2) based userspace implementation.
		// Regardless of the implementation, the underlying method remains the same.
		try
		{
			m_state->inspector->open_udig(m_state->config->m_single_buffer_dimension);
			falco_logger::log(LOG_INFO, "Starting capture with udig\n");
		}
		catch(sinsp_exception &e)
		{
			return run_result::fatal("Cannot use udig: " + std::string(e.what()));
		}
	}
	else if(m_options.gvisor_config != "") /* gvisor engine. */
	{
		try
		{
			m_state->inspector->open_gvisor(m_options.gvisor_config, m_options.gvisor_root);
			falco_logger::log(LOG_INFO, "Starting capture with gVisor. Configuration path: " + m_options.gvisor_config);
		}
		catch(sinsp_exception &e)
		{
			return run_result::fatal("Cannot use gVisor: " + std::string(e.what()));
		}
	}
	else if(m_options.modern_bpf) /* modern BPF engine. */
	{
		try
		{
			m_state->inspector->open_modern_bpf(m_state->config->m_single_buffer_dimension);
			falco_logger::log(LOG_INFO, "Starting capture with modern BPF probe.");
		}
		catch(sinsp_exception &e)
		{
			return run_result::fatal("Cannot use the modern BPF probe: " + std::string(e.what()));
		}
	}
	else if(getenv(FALCO_BPF_ENV_VARIABLE) != NULL) /* BPF engine. */
	{
		try
		{
			const char *bpf_probe_path = std::getenv(FALCO_BPF_ENV_VARIABLE);
			/* If the path is empty try to load the probe from the default path. */
			if(strncmp(bpf_probe_path, "", 1) == 0)
			{
				const char *home = std::getenv("HOME");
				if(!home)
				{
					return run_result::fatal("Cannot get the env variable 'HOME'");
				}
				char full_path[MAX_PROBE_PATH_SIZE];
				snprintf(full_path, MAX_PROBE_PATH_SIZE, "%s/%s", home, FALCO_PROBE_BPF_FILEPATH);
				bpf_probe_path = full_path;
			}
			m_state->inspector->open_bpf(m_state->config->m_single_buffer_dimension, bpf_probe_path);
			falco_logger::log(LOG_INFO, "Starting capture with BPF probe. BPF probe path: " + std::string(bpf_probe_path));
		}
		catch(sinsp_exception &e)
		{
			return run_result::fatal("Cannot use the BPF probe: " + std::string(e.what()));
		}
	}
	else /* Kernel module (default). */
	{
		try
		{
			m_state->inspector->open_kmod(m_state->config->m_single_buffer_dimension);
			falco_logger::log(LOG_INFO, "Starting capture with Kernel module.");
		}
		catch(sinsp_exception &e)
		{
			return run_result::fatal("Cannot use the kernel module: " + std::string(e.what()));
		}
	}

	if(m_state->config->m_single_buffer_dimension != 0)
	{
		falco_logger::log(LOG_INFO, "Buffer dimension: " + std::to_string(m_state->config->m_single_buffer_dimension) + " bytes\n");
	}

	// This must be done after the open
	if(!m_options.all_events)
	{
		m_state->inspector->start_dropping_mode(1);
	}

	return run_result::ok();
}

bool application::close_inspector(std::string &errstr)
{
	if(m_state->inspector != nullptr)
	{
		m_state->inspector->close();
	}

	return true;
}
