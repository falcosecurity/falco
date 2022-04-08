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

application::run_result application::validate_rules_files()
{
	run_result ret;

	if(m_options.validate_rules_filenames.size() > 0)
	{
		falco_logger::log(LOG_INFO, "Validating rules file(s):\n");
		for(auto file : m_options.validate_rules_filenames)
		{
			falco_logger::log(LOG_INFO, "   " + file + "\n");
		}
		for(auto file : m_options.validate_rules_filenames)
		{
			// Only include the prefix if there is more than one file
			std::string prefix = (m_options.validate_rules_filenames.size() > 1 ? file + ": " : "");
			try {
				m_state->engine->load_rules_file(file, m_options.verbose, m_options.all_events);
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
