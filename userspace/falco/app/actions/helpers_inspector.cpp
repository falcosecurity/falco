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
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <array>

#include <libsinsp/plugin_manager.h>
#include <configuration.h>

#include "helpers.h"

using namespace falco::app;
using namespace falco::app::actions;

namespace {

// Loads the Falco kernel module by invoking modprobe through a fixed,
// absolute path (instead of system("modprobe ...")). This avoids
// resolving "modprobe" via the PATH environment variable, which is
// attacker-controllable in some deployment scenarios (CWE-426: Untrusted
// Search Path). No shell is involved, and no user-controlled input is
// interpolated into the call.
bool falco_modprobe(const char* module_name) {
	static constexpr std::array<const char*, 2> modprobe_paths = {
	        "/usr/sbin/modprobe",
	        "/sbin/modprobe",
	};

	const char* modprobe_bin = nullptr;
	for(const auto& path : modprobe_paths) {
		if(access(path, X_OK) == 0) {
			modprobe_bin = path;
			break;
		}
	}

	if(modprobe_bin == nullptr) {
		falco_logger::log(falco_logger::level::ERR,
		                  "Could not find modprobe binary in /usr/sbin or /sbin\n");
		return false;
	}

	pid_t pid = fork();
	if(pid < 0) {
		falco_logger::log(falco_logger::level::ERR,
		                  std::string("fork() failed while loading kernel module: ") +
		                          strerror(errno) + "\n");
		return false;
	}

	if(pid == 0) {
		// Child process: redirect stdout/stderr to /dev/null (mirrors the
		// original "> /dev/null 2> /dev/null" redirection), then exec the
		// resolved absolute path directly. No shell is spawned.
		int devnull = open("/dev/null", O_WRONLY);
		if(devnull >= 0) {
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		execl(modprobe_bin, modprobe_bin, module_name, (char*)nullptr);
		// execl only returns on failure.
		_exit(127);
	}

	int status = 0;
	if(waitpid(pid, &status, 0) < 0) {
		falco_logger::log(falco_logger::level::ERR,
		                  std::string("waitpid() failed while loading kernel module: ") +
		                          strerror(errno) + "\n");
		return false;
	}

	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

}  // namespace

falco::app::run_result falco::app::actions::open_offline_inspector(falco::app::state& s) {
	try {
		s.offline_inspector->open_savefile(s.config->m_replay.m_capture_file);
		falco_logger::log(falco_logger::level::INFO,
		                  "Replaying events from the capture file: " +
		                          s.config->m_replay.m_capture_file + "\n");
		return run_result::ok();
	} catch(sinsp_exception& e) {
		return run_result::fatal("Could not open trace filename " +
		                         s.config->m_replay.m_capture_file + " for reading: " + e.what());
	}
}

falco::app::run_result falco::app::actions::open_live_inspector(falco::app::state& s,
                                                                std::shared_ptr<sinsp> inspector,
                                                                const std::string& source) {
	try {
		if(s.config->m_falco_libs_thread_table_size > 0) {
			// Default value is set in libs as part of the sinsp_thread_manager setup
			inspector->m_thread_manager->set_max_thread_table_size(
			        s.config->m_falco_libs_thread_table_size);
		}

		inspector->set_auto_threads_purging(true);
		inspector->set_auto_threads_purging_interval_s(
		        s.config->m_falco_libs_thread_table_auto_purging_interval_s);
		inspector->set_thread_timeout_s(
		        s.config->m_falco_libs_thread_table_auto_purging_thread_timeout_s);

		if(source != falco_common::syscall_source) /* Plugin engine */
		{
			for(const auto& p : inspector->get_plugin_manager()->plugins()) {
				// note: if more than one loaded plugin supports the given
				// event source, only the first one will be opened, following
				// the loading order specified in the Falco config.
				if(p->caps() & CAP_SOURCING && p->id() != 0 && p->event_source() == source) {
					auto cfg = s.plugin_configs.at(p->name());
					falco_logger::log(
					        falco_logger::level::INFO,
					        "Opening '" + source + "' source with plugin '" + cfg->m_name + "'");
					inspector->open_plugin(cfg->m_name,
					                       cfg->m_open_params,
					                       s.config->m_plugins_hostinfo
					                               ? sinsp_plugin_platform::SINSP_PLATFORM_HOSTINFO
					                               : sinsp_plugin_platform::SINSP_PLATFORM_GENERIC);
					return run_result::ok();
				}
			}
			return run_result::fatal("Can't find plugin for event source: " + source);
		} else if(s.is_nodriver()) /* nodriver engine. */
		{
			// when opening a capture with no driver, Falco will first check
			// if a plugin is capable of generating raw events from the libscap
			// event table (including system events), and if none is found it
			// will use the nodriver engine.
			for(const auto& p : inspector->get_plugin_manager()->plugins()) {
				if(p->caps() & CAP_SOURCING && p->id() == 0) {
					auto cfg = s.plugin_configs.at(p->name());
					falco_logger::log(
					        falco_logger::level::INFO,
					        "Opening '" + source + "' source with plugin '" + cfg->m_name + "'");
					inspector->open_plugin(cfg->m_name,
					                       cfg->m_open_params,
					                       sinsp_plugin_platform::SINSP_PLATFORM_FULL);
					return run_result::ok();
				}
			}
			falco_logger::log(falco_logger::level::INFO,
			                  "Opening '" + source + "' source with no driver\n");
			inspector->open_nodriver();
		} else if(s.is_modern_ebpf()) /* modern BPF engine. */
		{
			falco_logger::log(falco_logger::level::INFO,
			                  "Opening '" + source + "' source with modern BPF probe.");
			falco_logger::log(
			        falco_logger::level::INFO,
			        "One ring buffer every '" +
			                std::to_string(s.config->m_modern_ebpf.m_cpus_for_each_buffer) +
			                "' CPUs.");
			inspector->open_modern_bpf(s.syscall_buffer_bytes_size,
			                           s.config->m_modern_ebpf.m_cpus_for_each_buffer,
			                           true,
			                           s.selected_sc_set,
			                           s.config->m_modern_ebpf.m_disable_iterators);
		} else /* Kernel module (default). */
		{
			try {
				falco_logger::log(falco_logger::level::INFO,
				                  "Opening '" + source + "' source with Kernel module");
				inspector->open_kmod(s.syscall_buffer_bytes_size, s.selected_sc_set);
			} catch(sinsp_exception& e) {
				// Try to insert the Falco kernel module
				falco_logger::log(
				        falco_logger::level::INFO,
				        "Trying to inject the Kernel module and opening the capture again...");
				if(!falco_modprobe(DRIVER_NAME)) {
					falco_logger::log(falco_logger::level::ERR, "Unable to load the driver\n");
				}
				inspector->open_kmod(s.syscall_buffer_bytes_size, s.selected_sc_set);
			}
		}
	} catch(sinsp_exception& e) {
		return run_result::fatal(e.what());
	}

	return run_result::ok();
}
