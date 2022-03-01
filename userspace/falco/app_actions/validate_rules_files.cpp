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

#include "validate_rules_files.h"

namespace falco {
namespace app {

act_validate_rules_files::act_validate_rules_files(application &app)
	: init_action(app), m_name("validate rules files"),
	  m_prerequsites({"load plugins"})
{
}

act_validate_rules_files::~act_validate_rules_files()
{
}

const std::string &act_validate_rules_files::name()
{
	return m_name;
}

const std::list<std::string> &act_validate_rules_files::prerequsites()
{
	return m_prerequsites;
}

runnable_action::run_result act_validate_rules_files::run()
{
	run_result ret = {true, "", true};

	if(options().validate_rules_filenames.size() > 0)
	{
		falco_logger::log(LOG_INFO, "Validating rules file(s):\n");
		for(auto file : options().validate_rules_filenames)
		{
			falco_logger::log(LOG_INFO, "   " + file + "\n");
		}
		for(auto file : options().validate_rules_filenames)
		{
			// Only include the prefix if there is more than one file
			std::string prefix = (options().validate_rules_filenames.size() > 1 ? file + ": " : "");
			try {
				state().engine->load_rules_file(file, options().verbose, options().all_events);
			}
			catch(falco_exception &e)
			{
				printf("%s%s", prefix.c_str(), e.what());
				ret.success = false;
				ret.errstr = prefix +  e.what();
				ret.proceed = false;
				return ret;
			}
			printf("%sOk\n", prefix.c_str());
		}
		falco_logger::log(LOG_INFO, "Ok\n");
	}

	return ret;
}

}; // namespace application
}; // namespace falco

