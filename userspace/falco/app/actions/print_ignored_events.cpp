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
#include "helpers.h"
#include "falco_utils.h"

using namespace falco::app;
using namespace falco::app::actions;
using namespace falco::utils;


falco::app::run_result falco::app::actions::print_ignored_events(falco::app::state& s)
{

	if(!s.options.print_ignored_events)
	{
		return run_result::ok();
	}

	std::unique_ptr<sinsp> inspector(new sinsp());
	std::unordered_set<uint32_t> io_ppm_sc_set = enforce_io_ppm_sc_set();

	std::cout << "Ignored I/O syscall(s):" << std::endl;
	for(const auto& it : inspector->get_syscalls_names(io_ppm_sc_set))
	{
		std::cout << "- " << it.c_str() << std::endl;
	}
	std::cout << std::endl;

	return run_result::exit();
}
