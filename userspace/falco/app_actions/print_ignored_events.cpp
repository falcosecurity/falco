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

#include "application.h"

using namespace falco::app;

void application::print_all_ignored_events()
{
	std::unique_ptr<sinsp> inspector(new sinsp());
	sinsp_evttables* einfo = inspector->get_event_info_tables();
	const struct ppm_event_info* etable = einfo->m_event_info;
	const struct ppm_syscall_desc* stable = einfo->m_syscall_info_table;

	std::set<string> ignored_event_names;
	for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
	{
		if(!sinsp::simple_consumer_consider_evtnum(j))
		{
			std::string name = etable[j].name;
			// Ignore event names NA*
			if(name.find("NA") != 0)
			{
				ignored_event_names.insert(name);
			}
		}
	}

	for(uint32_t j = 0; j < PPM_SC_MAX; j++)
	{
		if(!sinsp::simple_consumer_consider_syscallid(j))
		{
			std::string name = stable[j].name;
			// Ignore event names NA*
			if(name.find("NA") != 0)
			{
				ignored_event_names.insert(name);
			}
		}
	}

	printf("Ignored Event(s):");
	for(auto it : ignored_event_names)
	{
		printf(" %s", it.c_str());
	}
	printf("\n");
}

application::run_result application::print_ignored_events()
{
	if(m_options.print_ignored_events)
	{
		print_all_ignored_events();
		return run_result::exit();
	}
	return run_result::ok();
}
