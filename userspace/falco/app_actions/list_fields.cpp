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

#include "fields_info.h"

#include "application.h"

using namespace falco::app;

application::run_result application::list_fields()
{
	if(m_options.list_fields)
	{
		if(m_options.list_source_fields != "" &&
		   !m_state->engine->is_source_valid(m_options.list_source_fields))
		{
			return run_result::fatal("Value for --list must be a valid source type");
		}
		m_state->engine->list_fields(m_options.list_source_fields, m_options.verbose, m_options.names_only, m_options.markdown);
		return run_result::exit();
	}

	if(m_options.list_syscall_events)
	{
		// We know this function doesn't hold into the raw pointer value
		list_events(m_state->inspector.get(), m_options.markdown);
		return run_result::exit();
	}

	return run_result::ok();
}
