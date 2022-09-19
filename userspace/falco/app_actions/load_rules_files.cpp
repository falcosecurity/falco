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
	/* Get the events from the rules. */
	std::set<uint16_t> rule_events;
	std::string source = falco_common::syscall_source;
	m_state->engine->evttypes_for_ruleset(source, rule_events);

	/* Get the events we consider interesting from the application state `ppm_sc` codes. */
	std::unique_ptr<sinsp> inspector(new sinsp());
	auto interesting_events = inspector->get_event_set_from_ppm_sc_set(m_state->ppm_sc_of_interest);
	std::unordered_set<uint32_t> ignored_events;

	for(const auto& it : rule_events)
	{
		/* If we have the old version of the event we will have also the recent one
		 * so we can avoid analyzing the presence of old events.
		 */
		if(sinsp::is_old_version_event(it))
		{
			continue;
		}

		/* Here we are interested only in syscall events the internal events are not
		 * altered without the `-A` flag.
		 *
		 * TODO: We could consider also the tracepoint events here but right now we don't have
		 * the support from the libraries.
		 */
		if(!sinsp::is_syscall_event(it))
		{
			continue;
		}

		/* If the event is not in this set it is not considered by Falco. */
		if(interesting_events.find(it) == interesting_events.end())
		{
			ignored_events.insert(it);
		}
	}

	if(ignored_events.empty())
	{
		return;
	}

	/* Get the names of the ignored events and print them. */
	auto event_names = inspector->get_events_names(ignored_events);
	std::cerr << std::endl << "Rules match ignored syscall: warning (ignored-evttype):" << std::endl;
	std::cerr << "Loaded rules match the following events:" << std::endl;
	for(const auto& it : event_names)
	{
		std::cerr << "\t- " << it.c_str() << std::endl;
	}
	std::cerr << "But these events are not returned unless running falco with -A" << std::endl << std::endl;
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
	// note: offline inspector contains all the loaded plugins
	std::string plugin_vers_err = "";
	std::vector<falco_engine::plugin_version_requirement> plugin_reqs;
	for (const auto &plugin : m_state->offline_inspector->get_plugin_manager()->plugins())
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
