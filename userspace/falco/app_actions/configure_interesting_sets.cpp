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

void application::configure_interesting_sets()
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
	m_state->ppm_sc_of_interest = inspector->enforce_simple_ppm_sc_set();

	/* In this case we get the tracepoints for the `libsinsp` state and we remove
	 * the `sched_switch` tracepoint since it is highly noisy and not so useful
	 * for our state/events enrichment.
	 */
	m_state->tp_of_interest = inspector->enforce_sinsp_state_tp();
	m_state->tp_of_interest.erase(SCHED_SWITCH);
}
