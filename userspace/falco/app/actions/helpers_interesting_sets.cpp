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

void extract_base_syscalls_names(const std::unordered_set<std::string>& base_syscalls_names, std::unordered_set<std::string>& positive_names, std::unordered_set<std::string>& negative_names)
{
	for (const std::string &ev : base_syscalls_names)
	{
		if (!ev.empty())
		{
			if (ev.at(0) == '!')
			{
				negative_names.insert(ev.substr(1, ev.size()));
			}
			else
			{
				positive_names.insert(ev);
			}
		}
	}
}

static libsinsp::events::set<ppm_event_code> extract_rules_event_set(falco::app::state& s)
{
	/* Get all (positive) PPME events from all rules as idx codes.
	 * Events names from negative filter expression statements are NOT included.
	 * PPME events in libsinsp are needed to map each event type into it's enter
	 * and exit event if applicable (e.g. for syscall events). */
	std::set<uint16_t> tmp;
	libsinsp::events::set<ppm_event_code> events;
	auto source = falco_common::syscall_source;
	s.engine->evttypes_for_ruleset(source, tmp);
	for (const auto &ev : tmp)
	{
		events.insert((ppm_event_code) ev);
	}
	return events;
}

static void check_for_rules_unsupported_events(falco::app::state& s, const libsinsp::events::set<ppm_event_code>& rules_event_set)
{
	/* Unsupported events are those events that are used in the rules
	 * but that are not part of the selected event set. For now, this
	 * is expected to happen only for high volume I/O syscalls for
	 * performance reasons. */
	auto unsupported_event_set = rules_event_set.diff(s.selected_event_set);
	if (unsupported_event_set.empty())
	{
		return;
	}

	/* Get the names of the events (syscall and non syscall events) that were not activated and print them. */
	auto names = libsinsp::events::event_set_to_names(unsupported_event_set);
	std::cerr << "Loaded rules match event types that are not activated or unsupported with current configuration: warning (unsupported-evttype): " + concat_set_in_order(names) << std::endl;
	std::cerr << "If syscalls in rules include high volume I/O syscalls (-> activate via `-A` flag), else syscalls might be associated with syscalls undefined on your architecture (https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html)" << std::endl;
}

static void select_event_set(falco::app::state& s, libsinsp::events::set<ppm_event_code>& rules_event_set)
{
	/* PPM syscall codes (sc) can be viewed as condensed libsinsp lookup table
	 * to map a system call name to it's actual system syscall id (as defined
	 * by the Linux kernel). Hence here we don't need syscall enter and exit distinction. */
	auto rules_names = libsinsp::events::event_set_to_names(rules_event_set);
	if (!rules_event_set.empty())
	{
		falco_logger::log(LOG_DEBUG, "(" + std::to_string(rules_names.size())
			+ ") events in rules: " + concat_set_in_order(rules_names) + "\n");
	}

	/* DEFAULT OPTION:
	* Current sinsp_state_sc_set() approach includes multiple steps:
	* (1) Enforce all positive syscalls from each Falco rule
	* (2) Enforce static `libsinsp` state set (non-adaptive, not conditioned by rules,
	* but based on PPME event table flags indicating generic sinsp state modifications)
	* -> Final set is union of (1) and (2)
	*
	* Fall-back if no valid positive syscalls in "base_syscalls",
	* e.g. when using "base_syscalls" only for negative syscalls.
	*/
	auto base_event_set = libsinsp::events::sinsp_state_event_set();
	s.selected_event_set = rules_event_set.merge(base_event_set);

	auto user_base_syscalls_names = s.config->m_base_syscalls;
	libsinsp::events::set<ppm_sc_code> valid_positive_syscalls;
	if (!user_base_syscalls_names.empty())
	{
		/* USER OVERRIDE INPUT OPTION "base_syscalls". */
		std::unordered_set<std::string> positive_names = {};
		std::unordered_set<std::string> negative_names = {};
		extract_base_syscalls_names(user_base_syscalls_names, positive_names, negative_names);

		valid_positive_syscalls = libsinsp::events::names_to_sc_set(positive_names);
		auto valid_negative_syscalls = libsinsp::events::names_to_sc_set(negative_names);

		if (!valid_positive_syscalls.empty())
		{
			/* Convert valid syscalls codes to event codes. */
			auto valid_positive_events = libsinsp::events::sc_set_to_event_set(valid_positive_syscalls);

			/* For now remove the sinsp_state_sc_set again. A possible future libs refactor can remove this need.
			 * That way we consistently use sinsp_state_event_set() which adds critical non syscalls events.
			 * This step prepares the sinsp state enforcement override w/ "base_syscalls" user input.
			*/
			auto sc_state_event_set = libsinsp::events::sc_set_to_event_set(libsinsp::events::sinsp_state_sc_set());
			s.selected_event_set = s.selected_event_set.diff(sc_state_event_set);
			s.selected_event_set = rules_event_set.merge(s.selected_event_set);

			/* Add valid base_syscalls events. */
			s.selected_event_set = s.selected_event_set.merge(valid_positive_events);

			auto valid_positive_syscalls_names = libsinsp::events::sc_set_to_names(valid_positive_syscalls);
			falco_logger::log(LOG_DEBUG, "+(" + std::to_string(valid_positive_syscalls_names.size())
				+ ") syscalls added (base_syscalls override): "
				+ concat_set_in_order(valid_positive_syscalls_names) + "\n");
		}

		if (!valid_negative_syscalls.empty())
		{
			/* Convert valid syscalls codes to event codes. */
			auto valid_negative_events = libsinsp::events::sc_set_to_event_set(valid_negative_syscalls);

			/* Remove negative base_syscalls events. */
			s.selected_event_set = s.selected_event_set.diff(valid_negative_events);
			rules_event_set = rules_event_set.diff(valid_negative_events);

			auto valid_negative_syscalls_names = libsinsp::events::sc_set_to_names(valid_negative_syscalls);
			falco_logger::log(LOG_DEBUG, "-(" + std::to_string(valid_negative_syscalls_names.size())
				+ ") syscalls removed (base_syscalls override): "
				+ concat_set_in_order(valid_negative_syscalls_names) + "\n");
		}
	}

	/* Derive the diff between the additional syscalls added via libsinsp state
	enforcement and the syscalls from each Falco rule. */
	auto non_rules_event_set = s.selected_event_set.diff(rules_event_set);
	if (!non_rules_event_set.empty() && valid_positive_syscalls.empty())
	{
		auto non_rules_event_set_names = libsinsp::events::event_set_to_names(non_rules_event_set);
		falco_logger::log(LOG_DEBUG, "+(" + std::to_string(non_rules_event_set_names.size())
			+ ") events (Falco's state engine set of events): "
			+ concat_set_in_order(non_rules_event_set_names) + "\n");
	}

	/* -A flag behavior:
	 * (1) default: all syscalls in rules included, sinsp state enforcement
	       without high volume I/O syscalls
	 * (2) -A flag set: all syscalls in rules included, sinsp state enforcement
	       and allowing high volume I/O syscalls */
	if(!s.options.all_events)
	{
		auto ignored_event_set = libsinsp::events::sc_set_to_event_set(libsinsp::events::io_sc_set());
		auto erased_event_set = s.selected_event_set.intersect(ignored_event_set);
		s.selected_event_set = s.selected_event_set.diff(ignored_event_set);
		if (!erased_event_set.empty())
		{
			auto erased_event_set_names = libsinsp::events::event_set_to_names(erased_event_set);
			falco_logger::log(LOG_DEBUG, "-(" + std::to_string(erased_event_set_names.size())
				+ ") ignored events (-> activate via `-A` flag): "
				+ concat_set_in_order(erased_event_set_names) + "\n");
		}
	}

	if (!s.selected_event_set.empty())
	{
		auto selected_event_set_names = libsinsp::events::event_set_to_names(s.selected_event_set);
		falco_logger::log(LOG_DEBUG, "(" + std::to_string(selected_event_set_names.size())
			+ ") events selected in total (final set): "
			+ concat_set_in_order(selected_event_set_names) + "\n");
	}
}

static void select_syscall_set(falco::app::state& s, const libsinsp::events::set<ppm_event_code>& rules_event_set)
{
	s.selected_sc_set = libsinsp::events::event_set_to_sc_set(s.selected_event_set);
	if (!s.selected_sc_set.empty())
	{
		auto selected_sc_set_names = libsinsp::events::sc_set_to_names(s.selected_sc_set);
		falco_logger::log(LOG_DEBUG, "(" + std::to_string(selected_sc_set_names.size())
			+ ") syscalls selected in total (final set): "
			+ concat_set_in_order(selected_sc_set_names) + "\n");
	}
}

static void select_kernel_tracepoint_set(falco::app::state& s)
{
	/* Kernel tracepoints activation
	 * Activate all tracepoints except `sched_switch` tracepoint since it
	 * is highly noisy and not so useful
	 * for our state/events enrichment. */
	s.selected_tp_set = libsinsp::events::sinsp_state_tp_set();
	s.selected_tp_set.remove(ppm_tp_code::SCHED_SWITCH);
}

falco::app::run_result falco::app::actions::configure_interesting_sets(falco::app::state& s)
{
	s.selected_event_set.clear();
	s.selected_sc_set.clear();
	s.selected_tp_set.clear();
	
	/* note: the set of events is the richest source of truth about
	 * the events generable by an inspector, because they also carry information
	 * about events that are old, unused, internal, and so on. As such, the
	 * strategy is to first craft the actual set of selected events, and
	 * then use it to obtain a set of enabled kernel tracepoints and a set
	 * of syscall codes. Those last two sets will be passed down to the
	 * inspector to instruct the kernel drivers on which kernel event should
	 * be collected at runtime. */
	auto rules_event_set = extract_rules_event_set(s);
	select_event_set(s, rules_event_set);
	check_for_rules_unsupported_events(s, rules_event_set);
	select_syscall_set(s, rules_event_set);
	select_kernel_tracepoint_set(s);
	return run_result::ok();
}
