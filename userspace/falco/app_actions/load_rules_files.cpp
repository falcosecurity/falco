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

void application::check_for_ignored_events()
{
	std::set<uint16_t> evttypes;
	sinsp_evttables* einfo = m_state->inspector->get_event_info_tables();
	const struct ppm_event_info* etable = einfo->m_event_info;

	m_state->engine->evttypes_for_ruleset(application::s_syscall_source, evttypes);

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
	run_result ret;

	string all_rules;

	if (!m_options.rules_filenames.empty())
	{
		m_state->config->m_rules_filenames = m_options.rules_filenames;
	}

	if(m_state->config->m_rules_filenames.empty())
	{
		ret.success = false;
		ret.errstr = "You must specify at least one rules file/directory via -r or a rules_file entry in falco.yaml";
		ret.proceed = false;
		return ret;
	}

	falco_logger::log(LOG_DEBUG, "Configured rules filenames:\n");
	for (auto filename : m_state->config->m_rules_filenames)
	{
		falco_logger::log(LOG_DEBUG, string("   ") + filename + "\n");
	}

	for (auto filename : m_state->config->m_rules_filenames)
	{
		falco_logger::log(LOG_INFO, "Loading rules from file " + filename + ":\n");
		uint64_t required_engine_version;

		try {
			m_state->engine->load_rules_file(filename, m_options.verbose, m_options.all_events, required_engine_version);
		}
		catch(falco_exception &e)
		{
			ret.success = false;
			ret.errstr = string("Could not load rules file ") + filename + ": " + e.what();
			ret.proceed = false;
			return ret;
		}
		m_state->required_engine_versions[filename] = required_engine_version;
	}

	// Ensure that all plugins are compatible with the loaded set of rules
	for(auto &info : m_state->plugin_infos)
	{
		std::string required_version;

		if(!m_state->engine->is_plugin_compatible(info.name, info.plugin_version.as_string(), required_version))
		{
			ret.success = false;
			ret.errstr = std::string("Plugin ") + info.name + " version " + info.plugin_version.as_string() + " not compatible with required plugin version " + required_version;
			ret.proceed = false;
		}
	}

	// Free-up memory for the rule loader, which is not used from now on
	m_state->engine->clear_loader();

	for (auto substring : m_options.disabled_rule_substrings)
	{
		falco_logger::log(LOG_INFO, "Disabling rules matching substring: " + substring + "\n");
		m_state->engine->enable_rule(substring, false);
	}

	if(m_options.disabled_rule_tags.size() > 0)
	{
		for(auto &tag : m_options.disabled_rule_tags)
		{
			falco_logger::log(LOG_INFO, "Disabling rules with tag: " + tag + "\n");
		}
		m_state->engine->enable_rule_by_tag(m_options.disabled_rule_tags, false);
	}

	if(m_options.enabled_rule_tags.size() > 0)
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
		ret.proceed = false;
		return ret;
	}

	if (!m_options.describe_rule.empty())
	{
		m_state->engine->describe_rule(&(m_options.describe_rule));
		ret.proceed = false;
		return ret;
	}

	return ret;
}
