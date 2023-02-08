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

static void check_for_ignored_events(falco::app::state& s)
{
	/* Get the events from the rules. */
	std::set<uint16_t> rule_events;
	std::string source = falco_common::syscall_source;
	s.engine->evttypes_for_ruleset(source, rule_events);

	/* Get the events we consider interesting from the application state `ppm_sc` codes. */
	std::unique_ptr<sinsp> inspector(new sinsp());
	std::unordered_set<uint32_t> events(rule_events.begin(), rule_events.end());

	auto event_names = inspector->get_events_names(events);
	for (const auto& n : inspector->get_events_names(s.ppm_event_info_of_interest))
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

	/* Reading a scap file we have no concepts of ignored events we read all we need. */
	if(!s.options.all_events && !s.is_capture_mode())
	{
		/* Here we have already initialized the application state with the interesting syscalls,
		 * so we have to check if any event types used by the loaded rules are not considered by 
		 * Falco interesting set.
		 */
		check_for_ignored_events(s);
	}

	if(s.options.all_events && s.options.modern_bpf)
	{
		/* Right now the modern BPF probe doesn't support the -A flag, we implemented just 
		 * the "simple set" syscalls.
		 */
		falco_logger::log(LOG_INFO, "The '-A' flag has no effect with the modern BPF probe, no further syscalls will be added\n");
	}

	if (s.options.describe_all_rules)
	{
		s.engine->describe_rule(NULL);
		return run_result::exit();
	}

	if (!s.options.describe_rule.empty())
	{
		s.engine->describe_rule(&(s.options.describe_rule));
		return run_result::exit();
	}

	return run_result::ok();
}
