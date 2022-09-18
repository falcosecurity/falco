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

/// TODO: probably in the next future would be more meaningful to print the ignored syscalls rather than
/// the ignored events, or maybe change the name of the events since right now they are almost the same of
/// the syscalls.
application::run_result application::print_ignored_events()
{
	/* If the option is true we print the events ignored with Falco `-A`, otherwise
	 * we return immediately.
	 */
	if(!m_options.print_ignored_events)
	{
		return run_result::ok();
	}

	/* Fill the application syscall and tracepoint sets.
	 * The execution will be interrupted after this call so
	 * we don't care if we populate these sets even if the `-A` flag
	 * is not set.
	 */
	configure_interesting_sets();

	/* Search for all the ignored syscalls. */
	std::unique_ptr<sinsp> inspector(new sinsp());
	std::unordered_set<uint32_t> all_ppm_sc = inspector->get_all_ppm_sc();
	std::unordered_set<uint32_t> ignored_ppm_sc;

	for(const auto& it : all_ppm_sc)
	{
		/* If the syscall is not in this set we ignore it. */
		if(m_state->ppm_sc_of_interest.find(it) == m_state->ppm_sc_of_interest.end())
		{
			ignored_ppm_sc.insert(it);
		}
	}

	/* Obtain the ignored events names from the ignored syscalls. */
	auto ignored_events = inspector->get_event_set_from_ppm_sc_set(ignored_ppm_sc);
	auto event_names = inspector->get_events_names(ignored_events);

	std::cout << "Ignored Event(s):" << std::endl;
	for(const auto& it : event_names)
	{
		std::cout << "- " << it.c_str() << std::endl;
	}
	std::cout << std::endl;

	return run_result::exit();
}
