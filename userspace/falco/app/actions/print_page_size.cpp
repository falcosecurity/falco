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

#include "actions.h"
#ifdef _WIN32
#include <windows.h>
#endif

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::print_page_size(const falco::app::state& s)
{
	if(s.options.print_page_size)
	{
#ifndef _WIN32
		long page_size = getpagesize();
#else
		SYSTEM_INFO sysInfo;

		GetSystemInfo(&sysInfo);

		long page_size = sysInfo.dwPageSize;
#endif
		if(page_size <= 0)
		{
			return run_result::fatal("\nUnable to get the system page size through 'getpagesize()'\n");
		}
		else
		{
			falco_logger::log(falco_logger::level::INFO, "Your system page size is: " + std::to_string(page_size) + " bytes\n");
		}
		return run_result::exit();
	}
	return run_result::ok();
}
