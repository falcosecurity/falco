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

#include <unordered_set>

using namespace falco::app;

bool application::check_rules_plugin_requirements(std::string& err)
{
	// Ensure that all plugins are compatible with the loaded set of rules
	// note: offline inspector contains all the loaded plugins
	std::vector<falco_engine::plugin_version_requirement> plugin_reqs;
	for (const auto &plugin : m_state->offline_inspector->get_plugin_manager()->plugins())
 	{
		falco_engine::plugin_version_requirement req;
		req.name = plugin->name();
		req.version = plugin->plugin_version().as_string();
		plugin_reqs.push_back(req);
 	}
	return m_state->engine->check_plugin_requirements(plugin_reqs, err);
}

void application::check_for_ignored_events()
{
	/* Get the events from the rules. */
	std::set<uint16_t> rule_events;
	std::string source = falco_common::syscall_source;
	m_state->engine->evttypes_for_ruleset(source, rule_events);

	/* Get the events we consider interesting from the application state `ppm_sc` codes. */
	std::unique_ptr<sinsp> inspector(new sinsp());
	std::unordered_set<uint32_t> events(rule_events.begin(), rule_events.end());

	auto event_names = inspector->get_events_names(events);
	for (const auto& n : inspector->get_events_names(m_state->ppm_event_info_of_interest))
	{
		event_names.erase(n);
	}

	if(event_names.empty())
	{
		return;
	}

	/* Get the names of the ignored events and print them. */
	std::cerr << "Rules match ignored syscall: warning (ignored-evttype):" << std::endl;
	std::cerr << "Loaded rules match the following events: ";
	bool first = true;
	for(const auto& it : event_names)
	{
		std::cerr << (first ? "" : ", ") << it.c_str();
		first = false;
	}
	std::cerr << std::endl << "These events might be associated with syscalls undefined on your architecture (please take a look here: https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html). If syscalls are instead defined, you have to run Falco with `-A` to catch these events" << std::endl;
}

application::run_result application::load_rules_files()
{
	std::string all_rules;

	if (!m_options.rules_filenames.empty())
	{
		m_state->config->m_rules_filenames = m_options.rules_filenames;
	}

	if(m_state->config->m_rules_filenames.empty())
	{
		return run_result::fatal("You must specify at least one rules file/directory via -r or a rules_file entry in falco.yaml");
	}

	falco_logger::log(LOG_DEBUG, "Configured rules filenames:\n");
	for (const auto& path : m_state->config->m_rules_filenames)
	{
		falco_logger::log(LOG_DEBUG, std::string("   ") + path + "\n");
	}

	for (const auto &path : m_state->config->m_rules_filenames)
	{
		falco_configuration::read_rules_file_directory(path, m_state->config->m_loaded_rules_filenames, m_state->config->m_loaded_rules_folders);
	}

	std::vector<std::string> rules_contents;
	falco::load_result::rules_contents_t rc;

	try {
		read_files(m_state->config->m_loaded_rules_filenames.begin(),
			   m_state->config->m_loaded_rules_filenames.end(),
			   rules_contents,
			   rc);
	}
	catch(falco_exception& e)
	{
		return run_result::fatal(e.what());
	}

	for(auto &filename : m_state->config->m_loaded_rules_filenames)
	{
		falco_logger::log(LOG_INFO, "Loading rules from file " + filename + "\n");
		std::unique_ptr<falco::load_result> res;

		res = m_state->engine->load_rules(rc.at(filename), filename);

		if(!res->successful())
		{
			// Return the summary version as the error
			return run_result::fatal(res->as_string(true, rc));
		}

		// If verbose is true, also print any warnings
		if(m_options.verbose && res->has_warnings())
		{
			fprintf(stderr, "%s\n", res->as_string(true, rc).c_str());
		}
	}

	std::string err = "";
	if (!check_rules_plugin_requirements(err))
	{
		return run_result::fatal(err);
	}

	for (const auto& substring : m_options.disabled_rule_substrings)
	{
		falco_logger::log(LOG_INFO, "Disabling rules matching substring: " + substring + "\n");
		m_state->engine->enable_rule(substring, false);
	}

	if(!m_options.disabled_rule_tags.empty())
	{
		for(auto &tag : m_options.disabled_rule_tags)
		{
			falco_logger::log(LOG_INFO, "Disabling rules with tag: " + tag + "\n");
		}
		m_state->engine->enable_rule_by_tag(m_options.disabled_rule_tags, false);
	}

	if(!m_options.enabled_rule_tags.empty())
	{
		// Since we only want to enable specific
		// rules, first disable all rules.
		m_state->engine->enable_rule(all_rules, false);
		for(auto &tag : m_options.enabled_rule_tags)
		{
			falco_logger::log(LOG_INFO, "Enabling rules with tag: " + tag + "\n");
		}
		m_state->engine->enable_rule_by_tag(m_options.enabled_rule_tags, true);
	}

	/* Reading a scap file we have no concepts of ignored events we read all we need. */
	if(!m_options.all_events && !is_capture_mode())
	{
		/* Here we have already initialized the application state with the interesting syscalls,
		 * so we have to check if any event types used by the loaded rules are not considered by 
		 * Falco interesting set.
		 */
		check_for_ignored_events();
	}

	if (m_options.describe_all_rules)
	{
		m_state->engine->describe_rule(NULL);
		return run_result::exit();
	}

	if (!m_options.describe_rule.empty())
	{
		m_state->engine->describe_rule(&(m_options.describe_rule));
		return run_result::exit();
	}

	return run_result::ok();
}
