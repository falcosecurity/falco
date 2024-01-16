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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <plugin_manager.h>
#include <configuration.h>

#include "helpers.h"

#ifdef _WIN32
#define PATH_MAX 260
#endif

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::open_offline_inspector(falco::app::state& s)
{
	try
	{
		s.offline_inspector->open_savefile(s.config->m_replay.m_capture_file);
		falco_logger::log(falco_logger::level::INFO, "Replaying events from the capture file: " + s.config->m_replay.m_capture_file + "\n");
		return run_result::ok();
	}
	catch (sinsp_exception &e)
	{
		return run_result::fatal("Could not open trace filename " + s.config->m_replay.m_capture_file + " for reading: " + e.what());
	}
}

falco::app::run_result falco::app::actions::open_live_inspector(
		falco::app::state& s,
		std::shared_ptr<sinsp> inspector,
		const std::string& source)
{
	try
	{
		if((s.config->m_metrics_flags & PPM_SCAP_STATS_STATE_COUNTERS))
		{
			inspector->set_sinsp_stats_v2_enabled();
		}

		if (source != falco_common::syscall_source) /* Plugin engine */
		{
			for (const auto& p: inspector->get_plugin_manager()->plugins())
			{
				// note: if more than one loaded plugin supports the given
				// event source, only the first one will be opened, following
				// the loading order specified in the Falco config.
				if (p->caps() & CAP_SOURCING && p->id() != 0 && p->event_source() == source)
				{
					auto cfg = s.plugin_configs.at(p->name());
					falco_logger::log(falco_logger::level::INFO, "Opening '" + source + "' source with plugin '" + cfg->m_name + "'");
					inspector->open_plugin(cfg->m_name, cfg->m_open_params);
					return run_result::ok();
				}
			}
			return run_result::fatal("Can't find plugin for event source: " + source);
		}
		else if (s.is_nodriver()) /* nodriver engine. */
		{
			// when opening a capture with no driver, Falco will first check
			// if a plugin is capable of generating raw events from the libscap
			// event table (including system events), and if none is found it
			// will use the nodriver engine.
			for (const auto& p: inspector->get_plugin_manager()->plugins())
			{
				if (p->caps() & CAP_SOURCING && p->id() == 0)
				{
					auto cfg = s.plugin_configs.at(p->name());
					falco_logger::log(falco_logger::level::INFO, "Opening '" + source + "' source with plugin '" + cfg->m_name + "'");
					inspector->open_plugin(cfg->m_name, cfg->m_open_params);
					return run_result::ok();
				}
			}
			falco_logger::log(falco_logger::level::INFO, "Opening '" + source + "' source with no driver\n");
			inspector->open_nodriver();
		}
		else if(s.is_gvisor()) /* gvisor engine. */
		{
			falco_logger::log(falco_logger::level::INFO, "Opening '" + source + "' source with gVisor. Configuration path: " + s.config->m_gvisor.m_config);
			inspector->open_gvisor(s.config->m_gvisor.m_config, s.config->m_gvisor.m_root);
		}
		else if(s.is_modern_ebpf()) /* modern BPF engine. */
		{
			falco_logger::log(falco_logger::level::INFO, "Opening '" + source + "' source with modern BPF probe.");
			falco_logger::log(falco_logger::level::INFO, "One ring buffer every '" + std::to_string(s.config->m_modern_ebpf.m_cpus_for_each_buffer) +  "' CPUs.");
			inspector->open_modern_bpf(s.syscall_buffer_bytes_size, s.config->m_modern_ebpf.m_cpus_for_each_buffer, true, s.selected_sc_set, s.config->m_modern_ebpf.m_filters);
		}
		else if(s.is_ebpf()) /* BPF engine. */
		{
			const char *bpf_probe_path = s.config->m_ebpf.m_probe_path.c_str();
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
			falco_logger::log(falco_logger::level::INFO, "Opening '" + source + "' source with BPF probe. BPF probe path: " + std::string(bpf_probe_path));
			inspector->open_bpf(bpf_probe_path, s.syscall_buffer_bytes_size, s.selected_sc_set);
		}
		else /* Kernel module (default). */
		{
			try
			{
				falco_logger::log(falco_logger::level::INFO, "Opening '" + source + "' source with Kernel module");
				inspector->open_kmod(s.syscall_buffer_bytes_size, s.selected_sc_set);
			}
			catch(sinsp_exception &e)
			{
				// Try to insert the Falco kernel module
				falco_logger::log(falco_logger::level::INFO, "Trying to inject the Kernel module and opening the capture again...");
				if(system("modprobe " DRIVER_NAME " > /dev/null 2> /dev/null"))
				{
					falco_logger::log(falco_logger::level::ERR, "Unable to load the driver\n");
				}
				inspector->open_kmod(s.syscall_buffer_bytes_size, s.selected_sc_set);
			}
		}
	}
	catch (sinsp_exception &e)
	{
		return run_result::fatal(e.what());
	}

	return run_result::ok();
}
