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

using namespace falco::app;
using namespace falco::app::actions;

struct event_entry
{
	bool is_enter;
	bool available;
	std::string name;
	const ppm_event_info* info;
};

static std::vector<event_entry> get_event_entries(bool include_generics, const libsinsp::events::set<ppm_event_code>& available)
{
	event_entry entry;
	std::vector<event_entry> events;

	// skip generic events
	for (const auto& e: libsinsp::events::all_event_set())
	{
		if (!libsinsp::events::is_generic(e)
			&& !libsinsp::events::is_old_version_event(e)
			&& !libsinsp::events::is_unused_event(e)
			&& !libsinsp::events::is_unknown_event(e))
		{
			entry.is_enter = PPME_IS_ENTER(e);
			entry.available = available.contains(e);
			entry.info = libsinsp::events::info(e);
			entry.name = entry.info->name;
			events.push_back(entry);
		}
	}

	if (include_generics)
	{
		// append generic events
		const auto names = libsinsp::events::event_set_to_names({ppm_event_code::PPME_GENERIC_E});
		for (const auto& name : names)
		{
			entry.is_enter = PPME_IS_ENTER(ppm_event_code::PPME_GENERIC_E);
			entry.available = available.contains(ppm_event_code::PPME_GENERIC_E);
			entry.info = libsinsp::events::info(ppm_event_code::PPME_GENERIC_E);
			entry.name = name;
			events.push_back(entry);

			entry.is_enter = PPME_IS_ENTER(ppm_event_code::PPME_GENERIC_X);
			entry.available = available.contains(ppm_event_code::PPME_GENERIC_X);
			entry.info = libsinsp::events::info(ppm_event_code::PPME_GENERIC_X);
			entry.name = name;
			events.push_back(entry);
		}
	}

	return events;
}

falco::app::run_result falco::app::actions::print_syscall_events(falco::app::state& s)
{
	if(s.options.list_syscall_events)
	{
		const auto events = get_event_entries(true, s.ppm_event_info_of_interest);

		if(s.options.markdown)
		{
			printf("Falco | Dir | Event\n");
			printf(":-----|:----|:-----\n");
		}

		for (const auto& e : events)
		{
			char dir = e.is_enter ? '>' : '<';
			if (s.options.markdown)
			{
				printf(e.available ? "Yes" : "No");
				printf(" | %c | **%s**(", dir, e.name.c_str());
			}
			else
			{
				printf("%c %s(", dir, e.name.c_str());
			}

			for(uint32_t k = 0; k < e.info->nparams; k++)
			{
				if(k != 0)
				{
					printf(", ");
				}

				printf("%s %s", param_type_to_string(e.info->params[k].type),
					e.info->params[k].name);
			}
			printf(")\n");
		}

		return run_result::exit();
	}

	return run_result::ok();
}
