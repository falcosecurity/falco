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
#include <string>

using namespace falco::app;

application::run_result application::validate_rules_files()
{
	if(m_options.validate_rules_filenames.size() > 0)
	{
		bool successful = true;
		std::string summary;

		falco_logger::log(LOG_INFO, "Validating rules file(s):\n");
		for(auto file : m_options.validate_rules_filenames)
		{
			falco_logger::log(LOG_INFO, "   " + file + "\n");
		}

		// The json output encompasses all files so the
		// validation result is a single json object.
		nlohmann::json results = nlohmann::json::array();

		for(auto file : m_options.validate_rules_filenames)
		{
			std::unique_ptr<falco::load_result> res;

			res = m_state->engine->load_rules_file(file);

			successful &= res->successful();

			if(summary != "")
			{
				summary += "\n";
			}
			summary += file + ": " + (res->successful() ? "Ok" : "Invalid");

			if(m_state->config->m_json_output)
			{
				results.push_back(res->as_json());
			}
			else
			{
				// Print the full output when verbose is true
				if(m_options.verbose &&
				   (!res->successful() || res->has_warnings()))
				{
					printf("%s\n", res->as_string(true).c_str());
				}
			}
		}

		if(m_state->config->m_json_output)
		{
			nlohmann::json res;
			res["falco_load_results"] = results;
			printf("%s\n", res.dump().c_str());
		}

		if(successful)
		{
			printf("%s\n", summary.c_str());
			return run_result::exit();
		}
		else
		{
			return run_result::fatal(summary);
		}
	}

	return run_result::ok();
}
