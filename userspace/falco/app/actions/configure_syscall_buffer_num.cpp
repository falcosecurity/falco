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

#include "actions.h"

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::configure_syscall_buffer_num(falco::app::state& s)
{
#ifdef __linux__
	if(!s.options.modern_bpf)
	{
		return run_result::ok();
	}

	ssize_t online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if(online_cpus <= 0)
	{
		return run_result::fatal("cannot get the number of online CPUs from the system\n");
	}

	if(s.config->m_cpus_for_each_syscall_buffer > online_cpus)
	{
		falco_logger::log(LOG_WARNING, "you required a buffer every '" + std::to_string(s.config->m_cpus_for_each_syscall_buffer) + "' CPUs but there are only '" + std::to_string(online_cpus) + "' online CPUs. Falco changed the config to: one buffer every '" + std::to_string(online_cpus) + "' CPUs\n");
		s.config->m_cpus_for_each_syscall_buffer = online_cpus;
	}
#endif
	return run_result::ok();
}
