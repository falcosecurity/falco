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
#include "helpers.h"
#include "../app.h"
#include "../../versions_info.h"

using namespace falco::app;
using namespace falco::app::actions;

struct event_entry
{
	bool is_enter;
	bool available;
	std::string name;
	const ppm_event_info* info;
};

struct events_by_category
{
	std::vector<event_entry> syscalls;
	std::vector<event_entry> tracepoints;
	std::vector<event_entry> pluginevents;
	std::vector<event_entry> metaevents;

	void add_event(ppm_event_code e, bool available, const std::string& name = "") {
		event_entry entry;

		entry.is_enter = PPME_IS_ENTER(e);
		entry.info = libsinsp::events::info(e);
		entry.available = available;

		if (name == "")
		{
			entry.name = entry.info->name;
		} else {
			entry.name = name;
		}

		if (libsinsp::events::is_syscall_event(e))
		{
			syscalls.push_back(entry);
			return;
		}

		if (libsinsp::events::is_tracepoint_event(e))
		{
			tracepoints.push_back(entry);
			return;
		}

		if (libsinsp::events::is_plugin_event(e))
		{
			pluginevents.push_back(entry);
			return;
		}

		if (libsinsp::events::is_metaevent(e))
		{
			metaevents.push_back(entry);
			return;
		}
	}
};

static struct events_by_category get_event_entries_by_category(bool include_generics, const libsinsp::events::set<ppm_event_code>& available)
{
	events_by_category result;

	// skip generic events
	for (const auto& e: libsinsp::events::all_event_set())
	{
		if (!libsinsp::events::is_generic(e)
			&& !libsinsp::events::is_old_version_event(e)
			&& !libsinsp::events::is_unused_event(e)
			&& !libsinsp::events::is_unknown_event(e))
		{
			result.add_event(e, available.contains(e));
		}
	}

	if (include_generics)
	{
		// append generic events
		const auto names = libsinsp::events::event_set_to_names({ppm_event_code::PPME_GENERIC_E});
		for (const auto& name : names)
		{
			result.add_event(ppm_event_code::PPME_GENERIC_E, available.contains(ppm_event_code::PPME_GENERIC_E), name);
			result.add_event(ppm_event_code::PPME_GENERIC_X, available.contains(ppm_event_code::PPME_GENERIC_X), name);
		}
	}

	return result;
}

static bool is_flag_type(ppm_param_type type)
{
	return (type == PT_FLAGS8 || type == PT_FLAGS16 || type == PT_FLAGS32 ||
			type == PT_ENUMFLAGS8 || type == PT_ENUMFLAGS16 || type == PT_ENUMFLAGS32);
}

static void print_param(const struct ppm_param_info *param, bool markdown) {
	printf("%s **%s**", param_type_to_string(param->type), param->name);

	if (is_flag_type(param->type) && param->info) {
		auto flag_info = static_cast<const ppm_name_value*>(param->info);

		printf(": ");
		for (size_t i = 0; flag_info[i].name != NULL; i++) {
			if (i != 0)
			{
				printf(", ");
			}

			if (markdown) {
				printf("*%s*", flag_info[i].name);
			} else {
				printf("%s", flag_info[i].name);
			}
		}
	}
}

static void print_events(const std::vector<event_entry> &events, bool markdown)
{
	if(markdown)
	{
		printf("Default | Dir | Name | Params \n");
		printf(":-------|:----|:-----|:-----\n");
	}

	for (const auto& e : events)
	{
		char dir = e.is_enter ? '>' : '<';
		if (markdown)
		{
			printf(e.available ? "Yes" : "No");
			printf(" | `%c` | `%s` | ", dir, e.name.c_str());
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

			print_param(&e.info->params[k], markdown);
		}
		if (markdown)
		{
			printf("\n");
		}
		else
		{
			printf(")\n");
		}
	}
}

falco::app::run_result falco::app::actions::print_syscall_events(falco::app::state& s)
{
	if(s.options.list_syscall_events)
	{
		const falco::versions_info info(s.offline_inspector);
		printf("The events below are valid for Falco *Schema Version*: %s\n", info.driver_schema_version.c_str());

		const libsinsp::events::set<ppm_event_code> available = libsinsp::events::all_event_set().diff(sc_set_to_event_set(falco::app::ignored_sc_set()));
		const struct events_by_category events_bc = get_event_entries_by_category(true, available);

		printf("## Syscall events\n\n");
		print_events(events_bc.syscalls, s.options.markdown);

		printf("\n\n## Tracepoint events\n\n");
		print_events(events_bc.tracepoints, s.options.markdown);

		printf("\n\n## Plugin events\n\n");
		print_events(events_bc.pluginevents, s.options.markdown);

		printf("\n\n## Metaevents\n\n");
		print_events(events_bc.metaevents, s.options.markdown);

		return run_result::exit();
	}

	return run_result::ok();
}
