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
#include <plugin_manager.h>

using namespace falco::app;

application::run_result application::list_plugins()
{
	if(m_options.list_plugins)
	{
		std::ostringstream os;
		const auto &plugins = m_state->inspector->get_plugin_manager()->plugins();
		for (auto &p : plugins)
		{
			os << "Name: " << p->name() << std::endl;
			os << "Description: " << p->description() << std::endl;
			os << "Contact: " << p->contact() << std::endl;
			os << "Version: " << p->plugin_version().as_string() << std::endl;
			os << "Capabilities: " << std::endl;
			if(p->caps() & CAP_SOURCING)
			{
				os << "  - Event Sourcing: (ID=" << p->id();
				os << ", source='" << p->event_source() << "')" << std::endl;
			}
			if(p->caps() & CAP_EXTRACTION)
			{
				os << "  - Field Extraction" << std::endl;
			}

			os << std::endl;
		}

		printf("%lu Plugins Loaded:\n\n%s\n", plugins.size(), os.str().c_str());
		return run_result::exit();
	}

	return run_result::ok();
}
