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

using namespace falco::app;
using namespace falco::app::actions;

static void extract_base_syscalls_names(
		const std::unordered_set<std::string>& base_syscalls_names,
		std::unordered_set<std::string>& user_positive_names,
		std::unordered_set<std::string>& user_negative_names)
{
	for (const std::string &ev : base_syscalls_names)
	{
		if (!ev.empty())
		{
			if (ev.at(0) == '!')
			{
				user_negative_names.insert(ev.substr(1, ev.size()));
			}
			else
			{
				user_positive_names.insert(ev);
			}
		}
	}
}

static void check_for_rules_unsupported_events(falco::app::state& s, const libsinsp::events::set<ppm_sc_code>& rules_sc_set)
{
	/* Unsupported events are those events that are used in the rules
	 * but that are not part of the selected event set. For now, this
	 * is expected to happen only for high volume syscalls for
	 * performance reasons. */
	auto unsupported_sc_set = rules_sc_set.diff(s.selected_sc_set);
	if (unsupported_sc_set.empty())
	{
		return;
	}

	/* Get the names of the events (syscall and non syscall events) that were not activated and print them. */
	auto names = libsinsp::events::sc_set_to_event_names(unsupported_sc_set);
	std::cerr << "Loaded rules match syscalls that are not activated (e.g. were removed via config settings such as no -A flag or negative base_syscalls elements) or unsupported with current configuration: warning (unsupported-evttype): " + concat_set_in_order(names) << std::endl;
	std::cerr << "If syscalls in rules include high volume syscalls (-> activate via `-A` flag), else syscalls may have been removed via base_syscalls option or might be associated with syscalls undefined on your architecture (https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html)" << std::endl;
}

static void select_event_set(falco::app::state& s, const libsinsp::events::set<ppm_sc_code>& rules_sc_set)
{
	/* PPM syscall codes (sc) can be viewed as condensed libsinsp lookup table
	 * to map a system call name to it's actual system syscall id (as defined
	 * by the Linux kernel). Hence here we don't need syscall enter and exit distinction. */
	auto rules_names = libsinsp::events::sc_set_to_event_names(rules_sc_set);
	if (!rules_sc_set.empty())
	{
		falco_logger::log(LOG_DEBUG, "(" + std::to_string(rules_names.size())
			+ ") syscalls in rules: " + concat_set_in_order(rules_names) + "\n");
	}

	/* DEFAULT OPTION:
	* Current `sinsp_state_sc_set()` approach includes multiple steps:
	* (1) Enforce all positive syscalls from each Falco rule
	* (2) Enforce static Falco state set (non-adaptive, not conditioned by rules,
	* but based on PPME event table flags indicating generic sinsp state modifications)
	* -> Final set is union of (1) and (2)
	*
	* Fall-back if no valid positive syscalls in `base_syscalls.custom_set`,
	* e.g. when using `base_syscalls.custom_set` only for negative syscalls.
	*/
	auto base_sc_set = libsinsp::events::sinsp_state_sc_set();

	/* USER OVERRIDE INPUT OPTION `base_syscalls.custom_set` etc. */
	std::unordered_set<std::string> user_positive_names = {};
	std::unordered_set<std::string> user_negative_names = {};
	extract_base_syscalls_names(s.config->m_base_syscalls_custom_set, user_positive_names, user_negative_names);
	auto user_positive_sc_set = libsinsp::events::event_names_to_sc_set(user_positive_names);
	auto user_negative_sc_set = libsinsp::events::event_names_to_sc_set(user_negative_names);

	auto user_positive_sc_set_names = libsinsp::events::sc_set_to_event_names(user_positive_sc_set);
	if (!user_positive_sc_set.empty())
	{
		// user overrides base event set
		base_sc_set = user_positive_sc_set;

		// we re-transform from sc_set to names to make
		// sure that bad user inputs are ignored
		falco_logger::log(LOG_DEBUG, "+(" + std::to_string(user_positive_sc_set_names.size())
			+ ") syscalls added (base_syscalls override): "
			+ concat_set_in_order(user_positive_sc_set_names) + "\n");
	}
	auto invalid_positive_sc_set_names = unordered_set_difference(user_positive_names, user_positive_sc_set_names);
	if (!invalid_positive_sc_set_names.empty())
	{
		falco_logger::log(LOG_WARNING, "Invalid (positive) syscall names: warning (base_syscalls override): "
			+ concat_set_in_order(invalid_positive_sc_set_names));
	}

	// selected events are the union of the rules events set and the
	// base events set (either the default or the user-defined one)
	s.selected_sc_set = rules_sc_set.merge(base_sc_set);

	/* REPLACE DEFAULT STATE, nothing else. Need to override s.selected_sc_set and have a separate logic block. */
	if (s.config->m_base_syscalls_repair && user_positive_sc_set.empty())
	{
		/* If `base_syscalls.repair` is specified, but `base_syscalls.custom_set` is empty we are replacing
		 * the default `sinsp_state_sc_set()` enforcement with the alternative `sinsp_repair_state_sc_set`.
		 * This approach only activates additional syscalls Falco needs beyond the
		 * syscalls defined in each Falco rule that are absolutely necessary based
		 * on the current rules configuration. */

		// returned set already has rules_sc_set merged
		s.selected_sc_set = libsinsp::events::sinsp_repair_state_sc_set(rules_sc_set);
	}

	auto user_negative_sc_set_names = libsinsp::events::sc_set_to_event_names(user_negative_sc_set);
	if (!user_negative_sc_set.empty())
	{
		/* Remove negative base_syscalls events. */
		s.selected_sc_set = s.selected_sc_set.diff(user_negative_sc_set);

		// we re-transform from sc_set to names to make
		// sure that bad user inputs are ignored
		falco_logger::log(LOG_DEBUG, "-(" + std::to_string(user_negative_sc_set_names.size())
			+ ") syscalls removed (base_syscalls override): "
			+ concat_set_in_order(user_negative_sc_set_names) + "\n");
	}
	auto invalid_negative_sc_set_names = unordered_set_difference(user_negative_names, user_negative_sc_set_names);
	if (!invalid_negative_sc_set_names.empty())
	{
		falco_logger::log(LOG_WARNING, "Invalid (negative) syscall names: warning (base_syscalls override): "
			+ concat_set_in_order(invalid_negative_sc_set_names));
	}

	/* Derive the diff between the additional syscalls added via libsinsp state
	enforcement and the syscalls from each Falco rule. We avoid printing
	this in case the user specified a custom set of base syscalls */
	auto non_rules_sc_set = s.selected_sc_set.diff(rules_sc_set);
	if (!non_rules_sc_set.empty() && user_positive_sc_set.empty())
	{
		auto non_rules_sc_set_names = libsinsp::events::sc_set_to_event_names(non_rules_sc_set);
		falco_logger::log(LOG_DEBUG, "+(" + std::to_string(non_rules_sc_set_names.size())
			+ ") syscalls (Falco's state engine set of syscalls): "
			+ concat_set_in_order(non_rules_sc_set_names) + "\n");
	}

	/* -A flag behavior:
	 * (1) default: all syscalls in rules included, sinsp state enforcement
	       without high volume syscalls
	 * (2) -A flag set: all syscalls in rules included, sinsp state enforcement
	       and allowing high volume syscalls */
	if(!s.options.all_events)
	{
		auto ignored_sc_set = falco::app::ignored_sc_set();
		auto erased_sc_set = s.selected_sc_set.intersect(ignored_sc_set);
		s.selected_sc_set = s.selected_sc_set.diff(ignored_sc_set);
		if (!erased_sc_set.empty())
		{
			auto erased_sc_set_names = libsinsp::events::sc_set_to_event_names(erased_sc_set);
			falco_logger::log(LOG_DEBUG, "-(" + std::to_string(erased_sc_set_names.size())
				+ ") ignored syscalls (-> activate via `-A` flag): "
				+ concat_set_in_order(erased_sc_set_names) + "\n");
		}
	}

	/* If a custom set is specified (positive, negative, or both), we attempt
	 * to repair it if configured to do so. */
	if (s.config->m_base_syscalls_repair && !s.config->m_base_syscalls_custom_set.empty())
	{
		/* If base_syscalls.repair is specified enforce state using `sinsp_repair_state_sc_set`.
		 * This approach is an alternative to the default `sinsp_state_sc_set()` state enforcement
		 * and only activates additional syscalls Falco needs beyond the syscalls defined in the
		 * Falco rules that are absolutely necessary based on the current rules configuration. */
		auto selected_sc_set = s.selected_sc_set;
		s.selected_sc_set = libsinsp::events::sinsp_repair_state_sc_set(s.selected_sc_set);
		auto repaired_sc_set = s.selected_sc_set.diff(selected_sc_set);
		if (!repaired_sc_set.empty())
		{
			auto repaired_sc_set_names = libsinsp::events::sc_set_to_event_names(repaired_sc_set);
			falco_logger::log(LOG_INFO, "+(" + std::to_string(repaired_sc_set_names.size())
				+ ") repaired syscalls: " + concat_set_in_order(repaired_sc_set_names) + "\n");
		}
	}

	/* Hidden safety enforcement for `base_syscalls.custom_set` user
	 * input override option (but keep as general safety enforcement)
	 * -> sched_process_exit trace point activation (procexit event)
	 * is necessary for continuous state engine cleanup,
	 * else memory would grow rapidly and linearly over time. */
	s.selected_sc_set.insert(ppm_sc_code::PPM_SC_SCHED_PROCESS_EXIT);

	if (!s.selected_sc_set.empty())
	{
		auto selected_sc_set_names = libsinsp::events::sc_set_to_event_names(s.selected_sc_set);
		falco_logger::log(LOG_DEBUG, "(" + std::to_string(selected_sc_set_names.size())
			+ ") syscalls selected in total (final set): "
			+ concat_set_in_order(selected_sc_set_names) + "\n");
	}
}

falco::app::run_result falco::app::actions::configure_interesting_sets(falco::app::state& s)
{
#ifdef __linux__
	if (s.engine == nullptr || s.config == nullptr)
	{
		return run_result::fatal("Broken 'configure_interesting_sets' preconditions: engine and config must be non-null");
	}

	s.selected_sc_set.clear();

	/* note: the set of events is the richest source of truth about
	 * the events generable by an inspector, because they also carry information
	 * about events that are old, unused, internal, and so on. As such, the
	 * strategy is to first craft the actual set of selected events, and
	 * then use it to obtain a set of enabled kernel tracepoints and a set
	 * of syscall codes. Those last two sets will be passed down to the
	 * inspector to instruct the kernel drivers on which kernel event should
	 * be collected at runtime. */
	auto rules_sc_set = s.engine->sc_codes_for_ruleset(falco_common::syscall_source);
	select_event_set(s, rules_sc_set);
	check_for_rules_unsupported_events(s, rules_sc_set);

#endif
	return run_result::ok();
}
