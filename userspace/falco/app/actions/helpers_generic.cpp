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
#include <plugin_manager.h>

#include <unordered_set>

using namespace falco::app;
using namespace falco::app::actions;

bool falco::app::actions::check_rules_plugin_requirements(falco::app::state& s, std::string& err)
{
	// Ensure that all plugins are compatible with the loaded set of rules
	// note: offline inspector contains all the loaded plugins
	std::vector<falco_engine::plugin_version_requirement> plugin_reqs;
	for (const auto &plugin : s.offline_inspector->get_plugin_manager()->plugins())
 	{
		falco_engine::plugin_version_requirement req;
		req.name = plugin->name();
		req.version = plugin->plugin_version().as_string();
		plugin_reqs.push_back(req);
 	}
	return s.engine->check_plugin_requirements(plugin_reqs, err);
}

void falco::app::actions::print_enabled_event_sources(falco::app::state& s)
{
	/* Print all enabled sources. */
	std::string str;
	for (const auto &src : s.enabled_sources)
	{
		str += str.empty() ? "" : ", ";
		str += src;
	}
	falco_logger::log(LOG_INFO, "Enabled event sources: " + str);

	// print some warnings to the user
	for (const auto& src : s.enabled_sources)
	{
		std::shared_ptr<sinsp_plugin> first_plugin = nullptr;
		const auto& plugins = s.offline_inspector->get_plugin_manager()->plugins();
		for (const auto& p : plugins)
		{
			if ((p->caps() & CAP_SOURCING)
					&& ((p->id() != 0 && src == p->event_source())
						|| (p->id() == 0 && src == falco_common::syscall_source)))
			{
				if (first_plugin == nullptr)
				{
					first_plugin = p;
				}
				else
				{
					if (src != falco_common::syscall_source || s.options.nodriver)
					{
						falco_logger::log(LOG_WARNING, "Enabled event source '"
							+ src + "' can be opened with multiple loaded plugins, will use only '"
							+ first_plugin->name() + "'");
					}
				}
			}
		}
		if (!first_plugin && s.options.nodriver)
		{
			falco_logger::log(LOG_WARNING, "Enabled event source '"
				+ src + "' will be opened with no driver, no event will be produced");
		}
	}
}

void falco::app::actions::format_plugin_info(std::shared_ptr<sinsp_plugin> p, std::ostream& os)
{
	os << "Name: " << p->name() << std::endl;
	os << "Description: " << p->description() << std::endl;
	os << "Contact: " << p->contact() << std::endl;
	os << "Version: " << p->plugin_version().as_string() << std::endl;
	os << "Capabilities: " << std::endl;
	if(p->caps() & CAP_SOURCING)
	{
		os << "  - Event Sourcing";
		if (p->id() != 0)
		{
			os << " (ID=" << p->id();
			os << ", source='" << p->event_source() << "')";
		}
		os << std::endl;
	}
	if(p->caps() & CAP_EXTRACTION)
	{
		os << "  - Field Extraction" << std::endl;
	}
}

