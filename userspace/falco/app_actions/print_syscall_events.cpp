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

#include <fields_info.h>

using namespace falco::app;

application::run_result application::print_syscall_events()
{
	if(m_options.list_syscall_events)
	{
		// We know this function doesn't hold into the raw pointer value
		std::unique_ptr<sinsp> inspector(new sinsp());
		list_events(inspector.get(), m_options.markdown);
		return run_result::exit();
	}

	return run_result::ok();
}
