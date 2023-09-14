// SPDX-License-Identifier: Apache-2.0
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

#include <string>

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::validate_rules_files(falco::app::state& s)
{
	if(s.options.validate_rules_filenames.size() > 0)
	{

		std::vector<std::string> rules_contents;
		falco::load_result::rules_contents_t rc;

		try {
			read_files(s.options.validate_rules_filenames.begin(),
				   s.options.validate_rules_filenames.end(),
				   rules_contents,
				   rc);
		}
		catch(falco_exception& e)
		{
			return run_result::fatal(e.what());
		}

		bool successful = true;

		// The validation result is *always* printed to
		// stdout. When json_output is true, the output is in
		// json format and contains all errors/warnings for
		// all files.
		//

		// When json_output is false, it contains a summary of
		// each file and whether it was valid or not, along
		// with any errors.  To match older falco behavior,
		// this *only* contains errors.
		//
		// So for each file stdout will contain:
		//
		// <filename>: Ok
		// or
		// <filename>: Invalid
		// [All Validation Errors]
		//
		// Warnings are only printed to stderr, and only
		// printed when verbose is true.
		std::string summary;

		falco_logger::log(LOG_INFO, "Validating rules file(s):\n");
		for(auto file : s.options.validate_rules_filenames)
		{
			falco_logger::log(LOG_INFO, "   " + file + "\n");
		}

		// The json output encompasses all files so the
		// validation result is a single json object.
		std::string err = "";
		nlohmann::json results = nlohmann::json::array();

		for(auto &filename : s.options.validate_rules_filenames)
		{
			std::unique_ptr<falco::load_result> res;

			res = s.engine->load_rules(rc.at(filename), filename);
			if (!check_rules_plugin_requirements(s, err))
			{
				return run_result::fatal(err);
			}

			successful &= res->successful();

			if(s.config->m_json_output)
			{
				results.push_back(res->as_json(rc));
			}
			
			if(summary != "")
			{
				summary += "\n";
			}

			// Add to the summary if not successful, or successful
			// with no warnings.
			if(!res->successful() || (res->successful() && !res->has_warnings()))
			{
				summary += res->as_string(true, rc);
			}
			else
			{
				// If here, there must be only warnings.
				// Add a line to the summary noting that the
				// file was ok with warnings, without actually
				// printing the warnings.
				summary += filename + ": Ok, with warnings";

				// If verbose is true, print the warnings now.
				if(s.options.verbose)
				{
					fprintf(stderr, "%s\n", res->as_string(true, rc).c_str());
				}
			}
		}

		if(s.config->m_json_output)
		{
			nlohmann::json res;
			res["falco_load_results"] = results;
			printf("%s\n", res.dump().c_str());
		}
		else
		{
			printf("%s\n", summary.c_str());
		}

		if(successful)
		{
			return run_result::exit();
		}
		else
		{
			return run_result::fatal(summary);
		}
	}

	return run_result::ok();
}
