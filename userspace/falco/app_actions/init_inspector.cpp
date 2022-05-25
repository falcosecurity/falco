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

application::run_result application::init_inspector()
{
	m_state->inspector->set_buffer_format(m_options.event_buffer_format);

	// If required, set the CRI paths
	for (auto &p : m_options.cri_socket_paths)
	{
		if (!p.empty())
		{
			m_state->inspector->add_cri_socket_path(p);
		}
	}

	// Decide whether to do sync or async for CRI metadata fetch
	m_state->inspector->set_cri_async(!m_options.disable_cri_async);

	//
	// If required, set the snaplen
	//
	if(m_options.snaplen != 0)
	{
		m_state->inspector->set_snaplen(m_options.snaplen);
	}

	if(!m_options.all_events)
	{
		// Drop EF_DROP_SIMPLE_CONS kernel side
		m_state->inspector->set_simple_consumer();
		// Eventually, drop any EF_DROP_SIMPLE_CONS event
		// that reached userspace (there are some events that are not syscall-based
		// like signaldeliver, that have the EF_DROP_SIMPLE_CONS flag)
		m_state->inspector->set_drop_event_flags(EF_DROP_SIMPLE_CONS);
	}

	m_state->inspector->set_hostname_and_port_resolution_mode(false);

	return run_result::ok();
}
