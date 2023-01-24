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

#include "helpers.h"
#include "actions.h"
#include "configure_interesting_sets.h"
#include <unordered_set>
#include <sinsp.h>
#include <sstream>

using namespace falco::app;
using namespace falco::app::actions;

extern sinsp_evttables g_infotables;

std::string concat_syscalls_names(std::unordered_set<std::string> const syscalls_names)
{
	std::set<std::string> syscalls_names_ordered = {};
	for (const auto &n : syscalls_names)
	{
		syscalls_names_ordered.insert(n);
	}
	std::stringstream ss;
	std::copy(syscalls_names_ordered.begin(), syscalls_names_ordered.end(),
	std::ostream_iterator<std::string>(ss, ", "));
	std::string syscalls_names_str = ss.str();
	return syscalls_names_str.substr(0, syscalls_names_str.size() - 2);
}

std::unordered_set<uint32_t> get_syscalls_ppm_codes(const std::unordered_set<std::string> syscalls_names)
{
	std::unordered_set<uint32_t> ppm_sc_set = {};
	for (int ppm_sc_code = 0; ppm_sc_code < PPM_SC_MAX; ++ppm_sc_code)
	{
		std::string ppm_sc_name = g_infotables.m_syscall_info_table[ppm_sc_code].name;
		if (syscalls_names.find(ppm_sc_name) != syscalls_names.end())
		{
			ppm_sc_set.insert(ppm_sc_code);
		}
	}
	return ppm_sc_set;
}

std::unordered_set<std::string> get_difference_syscalls_names(std::unordered_set<std::string> syscalls_names_reference, std::unordered_set<std::string> syscalls_names_comparison)
{
	std::unordered_set<std::string> out = syscalls_names_comparison;
	for (const auto &ppm_sc_name : syscalls_names_reference)
	{
		if (syscalls_names_comparison.find(ppm_sc_name) != syscalls_names_comparison.end())
		{
			out.erase(ppm_sc_name);
		}
	}
	return out;
}

void falco::app::actions::check_for_ignored_events(falco::app::state& s)
{
	/* Get the events from the rules. */
	std::set<uint16_t> rule_events;
	std::string source = falco_common::syscall_source;
	s.engine->evttypes_for_ruleset(source, rule_events);

	/* Get PPME events we consider interesting from the application state as idx codes. */
	std::unique_ptr<sinsp> inspector(new sinsp());
	std::unordered_set<uint32_t> ppme_events_codes(rule_events.begin(), rule_events.end());

	auto event_names = inspector->get_events_names(ppme_events_codes);
	for (const auto& n : inspector->get_events_names(s.ppm_event_info_of_interest))
	{
		event_names.erase(n);
	}

	/* Here the `libsinsp` state set is not enough, we need other syscalls used in the rules,
	 * so we use the `simple_set`, this `simple_set` contains all the syscalls of the `libsinsp` state
	 * plus syscalls for Falco default rules.
	 */
	s.ppm_sc_of_interest = inspector->enforce_simple_ppm_sc_set();
	s.ppm_event_info_of_interest = inspector->get_event_set_from_ppm_sc_set(s.ppm_sc_of_interest);

	if(event_names.empty())
	{
		return;
	}

	/* Get the names of the ignored events (syscall and non syscall events) and print them. */
	std::cerr << "Loaded rules match ignored event types: warning (ignored-evttype): " + concat_syscalls_names(event_names) << std::endl;
	std::cerr << "If syscalls in rules include high volume I/O syscalls (-> activate via `-A` flag), else (2) syscalls might be associated with syscalls undefined on your architecture (https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html)" << std::endl;

}

void falco::app::actions::extract_rules_event_names(falco::app::state& s, std::unique_ptr<sinsp>& inspector, std::unordered_set<std::string>& rules_evttypes_names)
{
	/* Get all (positive) PPME events from all rules as idx codes.
	 * Events names from negative filter expression statements are NOT included.
	 * PPME events in libsinsp are needed to map each event type into it's enter and exit event if applicable (e.g. for syscall events).
	*/
	std::set<uint16_t> rule_events;
	std::string source = falco_common::syscall_source;
	s.engine->evttypes_for_ruleset(source, rule_events);
	std::unordered_set<uint32_t> ppme_events_codes(rule_events.begin(), rule_events.end());

	/* Translate PPME event idx codes to consolidated event names.
	 * Those are the exact event type (evt.type) names from the rules and hence also contain non syscall names, e.g. "container".
	*/
	rules_evttypes_names = inspector->get_events_names(ppme_events_codes);
}

void falco::app::actions::activate_interesting_events(falco::app::state& s, std::unique_ptr<sinsp>& inspector)
{
	s.ppm_event_info_of_interest = inspector->get_event_set_from_ppm_sc_set(s.ppm_sc_of_interest);

	/* Fill-up the set of event infos of interest. This is needed to ensure the critical non syscall PPME events are activated as well, e.g. container or proc exit events. */
	for (uint32_t ev = 2; ev < PPM_EVENT_MAX; ev++)
	{
		if (!sinsp::is_old_version_event(ev)
				&& !sinsp::is_unused_event(ev)
				&& !sinsp::is_unknown_event(ev))
		{
			/* So far we only covered syscalls, so we add other kinds of
			interesting events. In this case, we are also interested in
			metaevents and in the procexit tracepoint event. */
			if (sinsp::is_metaevent(ev) || ev == PPME_PROCEXIT_1_E)
			{
				s.ppm_event_info_of_interest.insert(ev);
			}
		}
	}

	/* Reading a scap file we have no concepts of ignored events we read all we need. */
	if(!s.options.all_events && !s.is_capture_mode())
	{
		/* Here we have already initialized the application state with the interesting syscalls,
		 * so we have to check if any event types used by the loaded rules are not considered by
		 * Falco interesting set.
		 */
		falco::app::actions::check_for_ignored_events(s);
	}

}

void falco::app::actions::activate_interesting_syscalls(falco::app::state& s, std::unique_ptr<sinsp>& inspector, const std::unordered_set<std::string>& rules_evttypes_names)
{

	/* Translate PPME event names to PPM syscall idx codes.
	 * PPM syscall idx codes can be viewed as condensed libsinsp lookup table to map a system call name to it's actual system syscall id (as defined by the Linux kernel).
	 * Hence here we don't need syscall enter and exit distinction.
	*/
	std::unordered_set<uint32_t> rules_ppm_sc_set = get_syscalls_ppm_codes(rules_evttypes_names);
	std::unordered_set<std::string> rules_syscalls_names = inspector->get_syscalls_names(rules_ppm_sc_set);
	if (rules_syscalls_names.size() > 0)
	{
		falco_logger::log(LOG_INFO, "(" + std::to_string(rules_syscalls_names.size()) + ") syscalls activated in rules: " + concat_syscalls_names(rules_syscalls_names) + "\n");
	}

	/*
	*
	* DEFAULT OPTION:
	*
	* Current enforce_simple_ppm_sc_set approach includes multiple steps:
	* (1) Enforce all positive syscalls from each Falco rule
	* (2) Enforce a static set of syscalls in addition to the syscalls defined in Falco's rules
	* (3) Enforce `libsinsp` state set (non-adaptive, not conditioned by rules, but based on PPME event table flags indicating generic sinsp state modifications)
	* -> Final set is union of (1), (2) and (3)
	*
	*/

	/* Derive union of rules_ppm_sc_set (all syscalls defined in Falco rules) and enforced syscalls for libsinsp state and declare ppm_sc_of_interest. */
	s.ppm_sc_of_interest = inspector->enforce_simple_ppm_sc_set(rules_ppm_sc_set);

	/* Derive the diff between the additional syscalls added via libsinsp state enforcement and the syscalls from each Falco rule. */
	std::unordered_set<std::string> non_rules_syscalls_names = get_difference_syscalls_names(rules_syscalls_names, inspector->get_syscalls_names(s.ppm_sc_of_interest));

	if (non_rules_syscalls_names.size() > 0)
	{
		falco_logger::log(LOG_INFO, "+(" + std::to_string(non_rules_syscalls_names.size()) + ") syscalls activated (Falco's set of additional syscalls including syscalls needed for state engine): " + concat_syscalls_names(non_rules_syscalls_names) + "\n");
	}

	std::unordered_set<std::string> final_syscalls_names = inspector->get_syscalls_names(s.ppm_sc_of_interest);
	if (final_syscalls_names.size() > 0)
	{
		falco_logger::log(LOG_INFO, "(" + std::to_string(final_syscalls_names.size()) + ") syscalls in total activated (final set): " + concat_syscalls_names(final_syscalls_names) + "\n");
	}

}

void falco::app::actions::activate_interesting_kernel_tracepoints(falco::app::state& s, std::unique_ptr<sinsp>& inspector)
{
	/* Kernel tracepoints activation
	 *
	 * Activate all tracepoints except `sched_switch` tracepoint since it is highly noisy and not so useful
	 * for our state/events enrichment.
	 */
	s.tp_of_interest = inspector->enforce_sinsp_state_tp();
	s.tp_of_interest.erase(SCHED_SWITCH);
}

falco::app::run_result falco::app::actions::configure_interesting_sets(falco::app::state& s)
{

	std::unique_ptr<sinsp> inspector(new sinsp());
	std::unordered_set<std::string> rules_evttypes_names;

	falco::app::actions::extract_rules_event_names(s, inspector, rules_evttypes_names); // when reaching this code all evttypes are valid
	falco::app::actions::activate_interesting_syscalls(s, inspector, rules_evttypes_names);
	falco::app::actions::activate_interesting_events(s, inspector);
	falco::app::actions::activate_interesting_kernel_tracepoints(s, inspector);

	return run_result::ok();
}
