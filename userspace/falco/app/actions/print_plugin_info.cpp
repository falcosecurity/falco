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

#include "actions.h"
#include "helpers.h"

#include <plugin_manager.h>

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::print_plugin_info(falco::app::state& s)
{
	if(!s.options.print_plugin_info.empty())
	{
		std::unique_ptr<sinsp> inspector(new sinsp());
		for(auto &pc : s.config->m_plugins)
		{
			if (pc.m_name == s.options.print_plugin_info
				|| pc.m_library_path == s.options.print_plugin_info)
			{
				// load the plugin
				auto p = inspector->register_plugin(pc.m_library_path);

				// print plugin descriptive info
				std::ostringstream os;
				format_plugin_info(p, os);
				os << std::endl;
				printf("%s", os.str().c_str());

				// print plugin init schema
				os.str("");
				os.clear();
				ss_plugin_schema_type type;
				auto schema = p->get_init_schema(type);
				os << "Init config schema type: ";
				switch (type)
				{
					case SS_PLUGIN_SCHEMA_JSON:
						os << "JSON" << std::endl;
						break;
					case SS_PLUGIN_SCHEMA_NONE:
					default:
						os << "Not available, plugin does not implement the init config schema functionality" << std::endl;
						break;
				}
				os << schema << std::endl;
				os << std::endl;
				printf("%s", os.str().c_str());
				
				// init the plugin
				std::string err;
				if (!p->init(pc.m_init_config, err))
				{
					return run_result::fatal(err);
				}

				// print plugin suggested open parameters
				if (p->caps() & CAP_SOURCING)
				{
					os.str("");
					os.clear();
					auto params = p->list_open_params();
					if (params.empty())
					{
						os << "No suggested open params available: ";
						os << "plugin has not been configured, or it does not implement the open params suggestion functionality" << std::endl;
					}
					else
					{
						os << "Suggested open params:" << std::endl;
						for(auto &oparam : p->list_open_params())
						{
							if(oparam.desc == "")
							{
								os << oparam.value << std::endl;
							}
							else
							{
								os << oparam.value << ": " << oparam.desc << std::endl;
							}
						}
					}
					os << std::endl;
					printf("%s", os.str().c_str());
				}

				// exit
				return run_result::exit();
			}
		}
		return run_result::fatal("can't find plugin and print its info: " + s.options.print_plugin_info);
	}

	return run_result::ok();
}