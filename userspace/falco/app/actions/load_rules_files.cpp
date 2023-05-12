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

#include <unordered_set>

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::load_rules_files(falco::app::state& s)
{
	std::string all_rules;

	if (!s.options.rules_filenames.empty())
	{
		s.config->m_rules_filenames = s.options.rules_filenames;
	}

	if(s.config->m_rules_filenames.empty())
	{
		return run_result::fatal("You must specify at least one rules file/directory via -r or a rules_file entry in falco.yaml");
	}

	falco_logger::log(LOG_DEBUG, "Configured rules filenames:\n");
	for (const auto& path : s.config->m_rules_filenames)
	{
		falco_logger::log(LOG_DEBUG, std::string("   ") + path + "\n");
	}

	for (const auto &path : s.config->m_rules_filenames)
	{
		falco_configuration::read_rules_file_directory(path, s.config->m_loaded_rules_filenames, s.config->m_loaded_rules_folders);
	}

	std::vector<std::string> rules_contents;
	falco::load_result::rules_contents_t rc;

	try {
		read_files(s.config->m_loaded_rules_filenames.begin(),
			   s.config->m_loaded_rules_filenames.end(),
			   rules_contents,
			   rc);
	}
	catch(falco_exception& e)
	{
		return run_result::fatal(e.what());
	}

	for(auto &filename : s.config->m_loaded_rules_filenames)
	{
		falco_logger::log(LOG_INFO, "Loading rules from file " + filename + "\n");
		std::unique_ptr<falco::load_result> res;

		res = s.engine->load_rules(rc.at(filename), filename);

		if(!res->successful())
		{
			// Return the summary version as the error
			return run_result::fatal(res->as_string(true, rc));
		}

		// If verbose is true, also print any warnings
		if(s.options.verbose && res->has_warnings())
		{
			fprintf(stderr, "%s\n", res->as_string(true, rc).c_str());
		}
	}

	std::string err = "";
	if (!check_rules_plugin_requirements(s, err))
	{
		return run_result::fatal(err);
	}

	for (const auto& substring : s.options.disabled_rule_substrings)
	{
		falco_logger::log(LOG_INFO, "Disabling rules matching substring: " + substring + "\n");
		s.engine->enable_rule(substring, false);
	}

	if(!s.options.disabled_rule_tags.empty())
	{
		for(auto &tag : s.options.disabled_rule_tags)
		{
			falco_logger::log(LOG_INFO, "Disabling rules with tag: " + tag + "\n");
		}
		s.engine->enable_rule_by_tag(s.options.disabled_rule_tags, false);
	}

	if(!s.options.enabled_rule_tags.empty())
	{
		// Since we only want to enable specific
		// rules, first disable all rules.
		s.engine->enable_rule(all_rules, false);
		for(auto &tag : s.options.enabled_rule_tags)
		{
			falco_logger::log(LOG_INFO, "Enabling rules with tag: " + tag + "\n");
		}
		s.engine->enable_rule_by_tag(s.options.enabled_rule_tags, true);
	}

	if (s.options.describe_all_rules)
	{
		s.engine->describe_rule(NULL, s.config->m_json_output);
		return run_result::exit();
	}

	if (!s.options.describe_rule.empty())
	{
		s.engine->describe_rule(&(s.options.describe_rule), s.config->m_json_output);
		return run_result::exit();
	}

	return run_result::ok();
}
