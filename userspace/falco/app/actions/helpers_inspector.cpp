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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <plugin_manager.h>

#include "helpers.h"

/* DEPRECATED: we will remove it in Falco 0.34. */
#define FALCO_BPF_ENV_VARIABLE "FALCO_BPF_PROBE"

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::open_offline_inspector(falco::app::state& s)
{
	try
	{
		s.offline_inspector->open_savefile(s.options.trace_filename);
		falco_logger::log(LOG_INFO, "Reading system call events from file: " + s.options.trace_filename + "\n");
		return run_result::ok();
	}
	catch (sinsp_exception &e)
	{
		return run_result::fatal("Could not open trace filename " + s.options.trace_filename + " for reading: " + e.what());
	}
}

falco::app::run_result falco::app::actions::open_live_inspector(
		falco::app::state& s,
		std::shared_ptr<sinsp> inspector,
		const std::string& source)
{
	try
	{
		if (source != falco_common::syscall_source) /* Plugin engine */
		{
			for (const auto& p: inspector->get_plugin_manager()->plugins())
			{
				if (p->caps() & CAP_SOURCING && p->event_source() == source)
				{
					auto cfg = s.plugin_configs.at(p->name());
					falco_logger::log(LOG_INFO, "Opening capture with plugin '" + cfg->m_name + "'\n");
					inspector->open_plugin(cfg->m_name, cfg->m_open_params);
					return run_result::ok();
				}
			}
			return run_result::fatal("Can't open inspector for plugin event source: " + source);
		}
		else if (s.options.userspace) /* udig engine. */
		{
			// open_udig() is the underlying method used in the capture code to parse userspace events from the kernel.
			//
			// Falco uses a ptrace(2) based userspace implementation.
			// Regardless of the implementation, the underlying method remains the same.
			falco_logger::log(LOG_INFO, "Opening capture with udig\n");
			inspector->open_udig();
		}
		else if(!s.options.gvisor_config.empty()) /* gvisor engine. */
		{
			falco_logger::log(LOG_INFO, "Opening capture with gVisor. Configuration path: " + s.options.gvisor_config);
			inspector->open_gvisor(s.options.gvisor_config, s.options.gvisor_root);
		}
		else if(s.options.modern_bpf) /* modern BPF engine. */
		{
			falco_logger::log(LOG_INFO, "Opening capture with modern BPF probe.");
			falco_logger::log(LOG_INFO, "One ring buffer every '" + std::to_string(s.config->m_cpus_for_each_syscall_buffer) +  "' CPUs.");
			inspector->open_modern_bpf(s.syscall_buffer_bytes_size, s.config->m_cpus_for_each_syscall_buffer, true, s.selected_sc_set, s.selected_tp_set);
		}
		else if(getenv(FALCO_BPF_ENV_VARIABLE) != NULL) /* BPF engine. */
		{
			const char *bpf_probe_path = std::getenv(FALCO_BPF_ENV_VARIABLE);
			char full_path[PATH_MAX];
			/* If the path is empty try to load the probe from the default path. */
			if(strncmp(bpf_probe_path, "", 1) == 0)
			{
				const char *home = std::getenv("HOME");
				if(!home)
				{
					return run_result::fatal("Cannot get the env variable 'HOME'");
				}
				snprintf(full_path, PATH_MAX, "%s/%s", home, FALCO_PROBE_BPF_FILEPATH);
				bpf_probe_path = full_path;
			}
			falco_logger::log(LOG_INFO, "Opening capture with BPF probe. BPF probe path: " + std::string(bpf_probe_path));
			inspector->open_bpf(bpf_probe_path, s.syscall_buffer_bytes_size, s.selected_sc_set, s.selected_tp_set);
		}
		else /* Kernel module (default). */
		{
			try
			{
				falco_logger::log(LOG_INFO, "Opening capture with Kernel module");
				inspector->open_kmod(s.syscall_buffer_bytes_size, s.selected_sc_set, s.selected_tp_set);
			}
			catch(sinsp_exception &e)
			{
				// Try to insert the Falco kernel module
				falco_logger::log(LOG_INFO, "Trying to inject the Kernel module and opening the capture again...");
				if(system("modprobe " DRIVER_NAME " > /dev/null 2> /dev/null"))
				{
					falco_logger::log(LOG_ERR, "Unable to load the driver\n");
				}
				inspector->open_kmod(s.syscall_buffer_bytes_size, s.selected_sc_set, s.selected_tp_set);
			}
		}
	}
	catch (sinsp_exception &e)
	{
		return run_result::fatal(e.what());
	}

	return run_result::ok();
}
