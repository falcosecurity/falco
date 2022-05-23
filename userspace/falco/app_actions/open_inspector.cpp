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

typedef std::function<void(std::shared_ptr<sinsp> inspector)> open_t;

application::run_result application::open_inspector()
{
	if(is_capture_mode())
	{
		// Try to open the trace file as a
		// capture file first.
		try {
			m_state->inspector->open(m_options.trace_filename);
			falco_logger::log(LOG_INFO, "Reading system call events from file: " + m_options.trace_filename + "\n");
		}
		catch(sinsp_exception &e)
		{
			return run_result::fatal("Could not open trace filename " + m_options.trace_filename + " for reading: " + e.what());
		}
	}
	else
	{
		try
		{
			// open_udig() is the underlying method used in the capture code to parse userspace events from the kernel.
			//
			// Falco uses a ptrace(2) based userspace implementation.
			// Regardless of the implementation, the underlying method remains the same.
			if(m_options.userspace)
			{
				m_state->inspector->open_udig();
			}
			else
			{
				m_state->inspector->open();
			}
		}
		catch(sinsp_exception &e)
		{
			// If syscall input source is enabled and not through userspace instrumentation
			if (is_syscall_source_enabled() && !m_options.userspace)
			{
				// Try to insert the Falco kernel module
				if(system("modprobe " DRIVER_NAME " > /dev/null 2> /dev/null"))
				{
					falco_logger::log(LOG_ERR, "Unable to load the driver.\n");
				}
				m_state->inspector->open();
			}
			else
			{
				return run_result::fatal(e.what());
			}
		}
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
