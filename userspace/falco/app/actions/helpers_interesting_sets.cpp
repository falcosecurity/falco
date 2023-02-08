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

#include "helpers.h"

using namespace falco::app;
using namespace falco::app::actions;

void falco::app::actions::configure_interesting_sets(falco::app::state& s)
{
	/// TODO: in the next future we need to change the interface of `enforce_simple_ppm_sc_set`
	/// and `enforce_sinsp_state_tp` APIs, they shouldn't require an inspector to be called!
	std::unique_ptr<sinsp> inspector(new sinsp());

	/* Please note: here we fill these 2 sets because we are interested in only some features, if we leave
	 * them empty `libsinsp` will fill them with all the available syscalls and all the available tracepoints!
	 */

	/* Here the `libsinsp` state set is not enough, we need other syscalls used in the rules,
	 * so we use the `simple_set`, this `simple_set` contains all the syscalls of the `libsinsp` state
	 * plus syscalls for Falco default rules.
	 */
	s.ppm_sc_of_interest = inspector->enforce_simple_ppm_sc_set();
	s.ppm_event_info_of_interest = inspector->get_event_set_from_ppm_sc_set(s.ppm_sc_of_interest);

	/* Fill-up the set of event infos of interest */
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

	/* In this case we get the tracepoints for the `libsinsp` state and we remove
	 * the `sched_switch` tracepoint since it is highly noisy and not so useful
	 * for our state/events enrichment.
	 */
	s.tp_of_interest = inspector->enforce_sinsp_state_tp();
	s.tp_of_interest.erase(SCHED_SWITCH);
}
