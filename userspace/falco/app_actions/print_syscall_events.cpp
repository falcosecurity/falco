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

struct event_entry
{
	bool is_enter;
	bool available;
	std::string name;
	struct ppm_event_info info;
};

static std::vector<event_entry> get_event_entries(bool include_generics, const std::unordered_set<uint32_t>& available)
{
	event_entry entry;
	std::vector<event_entry> events;
	std::unique_ptr<sinsp> inspector(new sinsp());
	const struct ppm_event_info* etable = inspector->get_event_info_tables()->m_event_info;

	// skip generic events
	for(uint32_t evt = PPME_GENERIC_X + 1; evt < PPM_EVENT_MAX; evt++)
	{
		if (!sinsp::is_old_version_event(evt)
				&& !sinsp::is_unused_event(evt)
				&& !sinsp::is_unknown_event(evt))
		{
			entry.is_enter = PPME_IS_ENTER(evt);
			entry.available = available.find(evt) != available.end();
			entry.name = etable[evt].name;
			entry.info = etable[evt];
			events.push_back(entry);
		}
	}

	if (include_generics)
	{
		// append generic events
		const auto generic_syscalls = inspector->get_events_names({PPME_GENERIC_E});
		for (const auto& name : generic_syscalls)
		{
			for(uint32_t evt = PPME_GENERIC_E; evt <= PPME_GENERIC_X; evt++)
			{
				entry.is_enter = PPME_IS_ENTER(evt);
				entry.available = available.find(evt) != available.end();
				entry.name = name;
				entry.info = etable[evt];
				events.push_back(entry);
			}
		}
	}

	return events;
}

application::run_result application::print_syscall_events()
{
	if(m_options.list_syscall_events)
	{
		configure_interesting_sets();
		const auto events = get_event_entries(true, m_state->ppm_event_info_of_interest);

		if(m_options.markdown)
		{
			printf("Falco | Dir | Event\n");
			printf(":-----|:----|:-----\n");
		}

		for (const auto& e : events)
		{
			char dir = e.is_enter ? '>' : '<';
			if (m_options.markdown)
			{
				printf(e.available ? "Yes" : "No");
				printf(" | %c | **%s**(", dir, e.name.c_str());
			}
			else
			{
				printf("%c %s(", dir, e.name.c_str());
			}

			for(uint32_t k = 0; k < e.info.nparams; k++)
			{
				if(k != 0)
				{
					printf(", ");
				}

				printf("%s %s", param_type_to_string(e.info.params[k].type),
					e.info.params[k].name);
			}
			printf(")\n");
		}

		return run_result::exit();
	}

	return run_result::ok();
}
