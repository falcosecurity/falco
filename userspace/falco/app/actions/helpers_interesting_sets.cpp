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
#include "falco_utils.h"
#include <unordered_set>
#include <sinsp.h>
#include <sstream>

using namespace falco::app;
using namespace falco::app::actions;
using namespace falco::utils;

extern sinsp_evttables g_infotables;

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

void falco::app::actions::check_for_unsupported_events(falco::app::state& s, std::unique_ptr<sinsp>& inspector, const std::unordered_set<std::string>& rules_evttypes_names)
{
	std::unordered_set<std::string> intersection = unordered_set_intersection(inspector->get_events_names(s.ppm_event_info_of_interest), rules_evttypes_names);
	if(intersection.empty())
	{
		return;
	}
	std::unordered_set<std::string> unsupported = unordered_set_difference(rules_evttypes_names, inspector->get_events_names(s.ppm_event_info_of_interest));

	/* Get the names of the events (syscall and non syscall events) that were not activated and print them. */
	std::cerr << "Loaded rules match event types that are not activated or unsupported with current configuration: warning (unsupported-evttype): " + concat_set_in_order(unsupported) << std::endl;
	std::cerr << "If syscalls in rules include high volume I/O syscalls (-> activate via `-A` flag), else (2) syscalls might be associated with syscalls undefined on your architecture (https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html)" << std::endl;
}

void falco::app::actions::activate_interesting_events(falco::app::state& s, std::unique_ptr<sinsp>& inspector, const std::unordered_set<std::string>& rules_evttypes_names)
{
	std::unordered_set<uint32_t> ppm_event_info_of_interest = inspector->get_event_set_from_ppm_sc_set(s.ppm_sc_of_interest);
	s.ppm_event_info_of_interest = enforce_sinsp_state_ppme(ppm_event_info_of_interest);
	check_for_unsupported_events(s, inspector, rules_evttypes_names);
}

void falco::app::actions::activate_interesting_syscalls(falco::app::state& s, std::unique_ptr<sinsp>& inspector, const std::unordered_set<std::string>& rules_evttypes_names)
{

	/* Translate PPME event names to PPM syscall idx codes.
	 * PPM syscall idx codes can be viewed as condensed libsinsp lookup table to map a system call name to it's actual system syscall id (as defined by the Linux kernel).
	 * Hence here we don't need syscall enter and exit distinction.
	*/
	std::unordered_set<uint32_t> rules_ppm_sc_set = get_ppm_sc_set_from_syscalls(rules_evttypes_names);
	std::unordered_set<std::string> rules_syscalls_names = inspector->get_syscalls_names(rules_ppm_sc_set);
	if (rules_syscalls_names.size() > 0)
	{
		falco_logger::log(LOG_DEBUG, "(" + std::to_string(rules_syscalls_names.size()) + ") syscalls activated in rules: " + concat_set_in_order(rules_syscalls_names) + "\n");
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

	// TODO change to enforce_sinsp_state_ppm_sc
	s.ppm_sc_of_interest = inspector->enforce_simple_ppm_sc_set(rules_ppm_sc_set);

	/* Derive the diff between the additional syscalls added via libsinsp state enforcement and the syscalls from each Falco rule. */
	std::unordered_set<std::string> non_rules_syscalls_names = unordered_set_difference(inspector->get_syscalls_names(s.ppm_sc_of_interest), rules_syscalls_names);

	if (non_rules_syscalls_names.size() > 0)
	{
		falco_logger::log(LOG_DEBUG, "+(" + std::to_string(non_rules_syscalls_names.size()) + ") syscalls activated (Falco's set of additional syscalls including syscalls needed for state engine): " + concat_set_in_order(non_rules_syscalls_names) + "\n");
	}

	/* -A flag behavior:
	 * default: all syscalls in rules included, sinsp state enforcement without high volume I/O syscalls
	 * -A flag set: all syscalls in rules included, sinsp state enforcement and allowing high volume I/O syscalls
	*/

	if(!s.options.all_events)
	{
		std::unordered_set<uint32_t> io_ppm_sc_set = enforce_io_ppm_sc_set();
		std::unordered_set<std::string> erased_io_syscalls_names = inspector->get_syscalls_names(unordered_set_intersection(s.ppm_sc_of_interest, io_ppm_sc_set));
		s.ppm_sc_of_interest = unordered_set_difference(s.ppm_sc_of_interest, io_ppm_sc_set);

		if (erased_io_syscalls_names.size() > 0)
		{
			falco_logger::log(LOG_DEBUG, "-(" + std::to_string(erased_io_syscalls_names.size()) + ") high volume I/O syscalls (`-A` flag not set): " + concat_set_in_order(erased_io_syscalls_names) + "\n");
		}
	}

	std::unordered_set<std::string> final_syscalls_names = inspector->get_syscalls_names(s.ppm_sc_of_interest);

	if (final_syscalls_names.size() > 0)
	{
		falco_logger::log(LOG_DEBUG, "(" + std::to_string(final_syscalls_names.size()) + ") syscalls in total activated (final set): " + concat_set_in_order(final_syscalls_names) + "\n");
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
	falco::app::actions::activate_interesting_events(s, inspector, rules_evttypes_names);
	falco::app::actions::activate_interesting_kernel_tracepoints(s, inspector);

	return run_result::ok();
}
