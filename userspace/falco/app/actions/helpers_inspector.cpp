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
#include<fstream>
#include <plugin_manager.h>

#include "helpers.h"

/* DEPRECATED: we will remove it in Falco 0.34. */
#define FALCO_BPF_ENV_VARIABLE "FALCO_BPF_PROBE"
#define BPF_PROBE_PATH "/etc/clouddefense/probe.o"
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
		std::ifstream bpf_probe(BPF_PROBE_PATH);
		if(bpf_probe.good()){
			falco_logger::log(LOG_INFO,"Opening capture with BPF probe");
			inspector->open_bpf(BPF_PROBE_PATH,s.syscall_buffer_bytes_size,s.selected_sc_set);
		}
		else{
			return run_result::fatal("Error! BPF probe /etc/clouddefense/probe.o not found");
		}

	}
	catch (sinsp_exception &e)
	{
		return run_result::fatal(e.what());
	}

	return run_result::ok();
}
