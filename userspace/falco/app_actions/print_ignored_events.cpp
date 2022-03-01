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

#include "print_ignored_events.h"

namespace falco {
namespace app {

act_print_ignored_events::act_print_ignored_events(application &app)
	: init_action(app), m_name("print ignored events"),
	  m_prerequsites({"init inspector"})
{
}

act_print_ignored_events::~act_print_ignored_events()
{
}

const std::string &act_print_ignored_events::name()
{
	return m_name;
}

const std::list<std::string> &act_print_ignored_events::prerequsites()
{
	return m_prerequsites;
}

runnable_action::run_result act_print_ignored_events::run()
{
	run_result ret = {true, "", true};

	if(options().print_ignored_events)
	{
		print_all_ignored_events();
		ret.proceed = false;
	}

	return ret;
}

void act_print_ignored_events::print_all_ignored_events()
{
	sinsp_evttables* einfo = state().inspector->get_event_info_tables();
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

}; // namespace application
}; // namespace falco

