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

#include <plugin_manager.h>

#include "application.h"

using namespace falco::app;

application::run_result application::open_offline_inspector()
{
	try
	{
		m_state->offline_inspector->open(m_options.trace_filename);
		falco_logger::log(LOG_INFO, "Reading system call events from file: " + m_options.trace_filename + "\n");
		return run_result::ok();
	}
	catch (sinsp_exception &e)
	{
		return run_result::fatal("Could not open trace filename " + m_options.trace_filename + " for reading: " + e.what());
	}
}

application::run_result application::open_live_inspector(
		std::shared_ptr<sinsp> inspector,
		const std::string& source)
{
	try
	{
		if (source != falco_common::syscall_source)
		{
			for (const auto p: inspector->get_plugin_manager()->plugins())
			{
				if (p->caps() & CAP_SOURCING && p->event_source() == source)
				{
					auto cfg = m_state->plugin_configs.at(p->name());
					inspector->set_input_plugin(cfg->m_name, cfg->m_open_params);
					inspector->open();
					return run_result::ok();
				}
			}
			return run_result::fatal("Can't open inspector for plugin event source: " + source);
		}

		if (m_options.userspace)
		{
			// open_udig() is the underlying method used in the capture code to parse userspace events from the kernel.
			//
			// Falco uses a ptrace(2) based userspace implementation.
			// Regardless of the implementation, the underlying method remains the same.
			inspector->open_udig();
		}
		else if(m_options.gvisor_config != "")
		{
			falco_logger::log(LOG_INFO, "Enabled event collection from gVisor. Configuration path: " + m_options.gvisor_config);
			inspector->open_gvisor(m_options.gvisor_config, m_options.gvisor_root);
		}
		else
		{
			inspector->open();
		}
	}
	catch (sinsp_exception &e)
	{
		// If syscall input source is enabled and not through userspace instrumentation
		if (m_options.gvisor_config.empty() && !m_options.userspace)
		{
			// Try to insert the Falco kernel module
			if(system("modprobe " DRIVER_NAME " > /dev/null 2> /dev/null"))
			{
				falco_logger::log(LOG_ERR, "Unable to load the driver.\n");
			}
			inspector->open();
		}
		else
		{
			return run_result::fatal(e.what());
		}
	}

	/// TODO: we can add a method to the inspector that tells us what 
	/// is the underline engine used. Right now we print something only 
	/// in case of BPF engine
	if (inspector->is_bpf_enabled())
	{
		falco_logger::log(LOG_INFO, "Falco is using the BPF probe\n");	
	}

	// This must be done after the open
	if (!m_options.all_events)
	{
		inspector->start_dropping_mode(1);
	}

	return run_result::ok();
}
