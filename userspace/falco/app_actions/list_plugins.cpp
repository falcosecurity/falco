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

#include "list_plugins.h"

namespace falco {
namespace app {

act_list_plugins::act_list_plugins(application &app)
	: init_action(app), m_name("list plugins"),
	  m_prerequsites({"load plugins"})
{
}

act_list_plugins::~act_list_plugins()
{
}

const std::string &act_list_plugins::name()
{
	return m_name;
}

const std::list<std::string> &act_list_plugins::prerequsites()
{
	return m_prerequsites;
}

runnable_action::run_result act_list_plugins::run()
{
	run_result ret = {true, "", true};

	if(options().list_plugins)
	{
		std::ostringstream os;

		for(auto &info : state().plugin_infos)
		{
			os << "Name: " << info.name << std::endl;
			os << "Description: " << info.description << std::endl;
			os << "Contact: " << info.contact << std::endl;
			os << "Version: " << info.plugin_version.as_string() << std::endl;

			if(info.type == TYPE_SOURCE_PLUGIN)
			{
				os << "Type: source plugin" << std::endl;
				os << "ID: " << info.id << std::endl;
			}
			else
			{
				os << "Type: extractor plugin" << std::endl;
			}
			os << std::endl;
		}

		printf("%lu Plugins Loaded:\n\n%s\n", state().plugin_infos.size(), os.str().c_str());
		ret.proceed = false;
	}

	return ret;
}

}; // namespace application
}; // namespace falco

