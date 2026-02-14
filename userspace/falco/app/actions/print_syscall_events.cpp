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
#include "event_formatter.h"
#include "../app.h"
#include "../../versions_info.h"

using namespace falco::app;
using namespace falco::app::actions;

struct events_by_category {
	std::vector<event_entry> syscalls;
	std::vector<event_entry> tracepoints;
	std::vector<event_entry> pluginevents;
	std::vector<event_entry> metaevents;

	void add_event(ppm_event_code e, bool available, const std::string& name = "") {
		event_entry entry;

		entry.is_enter = PPME_IS_ENTER(e);
		entry.info = libsinsp::events::info(e);
		entry.available = available;

		if(name == "") {
			entry.name = entry.info->name;
		} else {
			entry.name = name;
		}

		if(libsinsp::events::is_syscall_event(e)) {
			syscalls.push_back(entry);
			return;
		}

		if(libsinsp::events::is_tracepoint_event(e)) {
			tracepoints.push_back(entry);
			return;
		}

		if(libsinsp::events::is_plugin_event(e)) {
			pluginevents.push_back(entry);
			return;
		}

		if(libsinsp::events::is_metaevent(e)) {
			metaevents.push_back(entry);
			return;
		}
	}

	void print_all(EventFormatter& formatter) {
		formatter.begin_category("Syscall events");
		for(const auto& e : syscalls) {
			formatter.print_event(e);
		}
		formatter.end_category();

		formatter.begin_category("Tracepoint events");
		for(const auto& e : tracepoints) {
			formatter.print_event(e);
		}
		formatter.end_category();

		formatter.begin_category("Plugin events");
		for(const auto& e : pluginevents) {
			formatter.print_event(e);
		}
		formatter.end_category();

		formatter.begin_category("Metaevents");
		for(const auto& e : metaevents) {
			formatter.print_event(e);
		}
		formatter.end_category();
	}
};

static struct events_by_category get_event_entries_by_category(
        bool include_generics,
        const libsinsp::events::set<ppm_event_code>& available) {
	events_by_category result;

	// skip generic events
	for(const auto& e : libsinsp::events::all_event_set()) {
		if(!libsinsp::events::is_generic(e) && !libsinsp::events::is_old_version_event(e) &&
		   !libsinsp::events::is_unused_event(e) && !libsinsp::events::is_unknown_event(e)) {
			result.add_event(e, available.contains(e));
		}
	}

	if(include_generics) {
		// append generic events
		const auto names = libsinsp::events::event_set_to_names({ppm_event_code::PPME_GENERIC_E});
		for(const auto& name : names) {
			result.add_event(ppm_event_code::PPME_GENERIC_E,
			                 available.contains(ppm_event_code::PPME_GENERIC_E),
			                 name);
			result.add_event(ppm_event_code::PPME_GENERIC_X,
			                 available.contains(ppm_event_code::PPME_GENERIC_X),
			                 name);
		}
	}

	return result;
}

falco::app::run_result falco::app::actions::print_syscall_events(falco::app::state& s) {
	if(!s.options.list_syscall_events) {
		return run_result::ok();
	}

	const falco::versions_info info(s.offline_inspector);
	const libsinsp::events::set<ppm_event_code> available = libsinsp::events::all_event_set().diff(
	        sc_set_to_event_set(falco::app::ignored_sc_set()));
	struct events_by_category events_bc = get_event_entries_by_category(true, available);

	// Create the appropriate formatter and use it
	auto formatter = EventFormatter::create(s.options.output_fmt);
	formatter->begin(info.driver_schema_version);
	events_bc.print_all(*formatter);
	formatter->end();

	return run_result::exit();
}
