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

void application::check_for_ignored_events()
{
	std::set<uint16_t> evttypes;
	std::unique_ptr<sinsp> inspector(new sinsp());
	sinsp_evttables* einfo = inspector->get_event_info_tables();
	const struct ppm_event_info* etable = einfo->m_event_info;

	std::string source = falco_common::syscall_source;
	m_state->engine->evttypes_for_ruleset(source, evttypes);

	// Save event names so we don't warn for both the enter and exit event.
	std::set<std::string> warn_event_names;

	for(auto evtnum : evttypes)
	{
		if(evtnum == PPME_GENERIC_E || evtnum == PPME_GENERIC_X)
		{
			continue;
		}

		if(!sinsp::simple_consumer_consider_evtnum(evtnum))
		{
			std::string name = etable[evtnum].name;
			if(warn_event_names.find(name) == warn_event_names.end())
			{
				warn_event_names.insert(name);
			}
		}
	}

	// Print a single warning with the list of ignored events
	if (!warn_event_names.empty())
	{
		std::string skipped_events;
		bool first = true;
		for (const auto& evtname : warn_event_names)
		{
			if (first)
			{
				skipped_events += evtname;
				first = false;
			} else
			{
				skipped_events += "," + evtname;
			}
		}
		fprintf(stderr,"Rules match ignored syscall: warning (ignored-evttype):\n         loaded rules match the following events: %s;\n         but these events are not returned unless running falco with -A\n", skipped_events.c_str());
	}
}

application::run_result application::load_rules_files()
{
	string all_rules;

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
		falco_logger::log(LOG_DEBUG, string("   ") + path + "\n");
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

	// Ensure that all plugins are compatible with the loaded set of rules
	std::string plugin_vers_err = "";
	std::vector<falco_engine::plugin_version_requirement> plugin_reqs;
	for (const auto &plugin : m_state->inspector->get_plugin_manager()->plugins())
 	{
		falco_engine::plugin_version_requirement req;
		req.name = plugin->name();
		req.version = plugin->plugin_version().as_string();
		plugin_reqs.push_back(req);
 	}
	if (!m_state->engine->check_plugin_requirements(plugin_reqs, plugin_vers_err))
	{
		return run_result::fatal(plugin_vers_err);
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

	if(!m_options.all_events)
	{
		// For syscalls, see if any event types used by the
		// loaded rules are ones with the EF_DROP_SIMPLE_CONS
		// label.
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
