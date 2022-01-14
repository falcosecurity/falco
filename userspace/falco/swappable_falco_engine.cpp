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

#include <fstream>

#include "logger.h"
#include "swappable_falco_engine.h"

std::string swappable_falco_engine::syscall_source = "syscall";
std::string swappable_falco_engine::k8s_audit_source = "k8s_audit";

swappable_falco_engine::config::config()
	: json_output(false), replace_container_info(false),
	  event_sources{syscall_source, k8s_audit_source}
{
}

swappable_falco_engine::config::~config()
{
}

bool swappable_falco_engine::config::contains_event_source(const std::string &source)
{
	return (event_sources.find(source) != event_sources.end());
}

bool swappable_falco_engine::open_files(std::list<std::string> &filenames,
					std::list<swappable_falco_engine::rulesfile> &rulesfiles,
					std::string &errstr)
{
	rulesfiles.clear();

	for(const auto &file : filenames)
	{
		std::ifstream is;

		is.open(file);
		if (!is.is_open())
		{
			errstr = "Could not open rules filename " +
				file + " " + "for reading";
			return false;
		}

		std::string content((istreambuf_iterator<char>(is)),
				    istreambuf_iterator<char>());

		rulesfile rf{file, content, 0};

		rulesfiles.emplace_back(rf);
	}

	return true;
}

swappable_falco_engine::swappable_falco_engine()
{
}

swappable_falco_engine::~swappable_falco_engine()
{

}

bool swappable_falco_engine::init(swappable_falco_engine::config &cfg, sinsp *inspector, std::string &errstr)
{
	m_config = cfg;
	m_inspector = inspector;

	// Initialize some engine with no rules
	std::list<swappable_falco_engine::rulesfile> empty;
	return replace(empty, errstr);
}

std::shared_ptr<falco_engine> swappable_falco_engine::engine()
{
	std::shared_ptr<falco_engine> new_engine;

	while(m_pending_falco_engine.try_pop(new_engine))
	{
		m_engine=new_engine;
	}

	if(m_engine == NULL)
	{
		throw falco_exception("No engine, must call replace() first");
	}

	return m_engine;
}

filter_check_list &swappable_falco_engine::plugin_filter_checks()
{
	return m_plugin_filter_checks;
}

bool swappable_falco_engine::replace(const std::list<swappable_falco_engine::rulesfile> &rulesfiles, std::string &errstr)
{
	std::shared_ptr<falco_engine> new_engine;

	new_engine = create_new(rulesfiles, errstr);

	if (new_engine == NULL)
	{
		return false;
	}

	m_pending_falco_engine.push(new_engine);

	return true;
}

bool swappable_falco_engine::validate(const std::list<swappable_falco_engine::rulesfile> &rulesfiles, std::string &errstr)
{
	std::shared_ptr<falco_engine> new_engine;

	new_engine = create_new(rulesfiles, errstr);

	return (new_engine != NULL);
}

std::shared_ptr<falco_engine> swappable_falco_engine::create_new(const std::list<swappable_falco_engine::rulesfile> &rulesfiles,
								 std::string &errstr)
{
	std::shared_ptr<falco_engine> ret = make_shared<falco_engine>();

	if(!m_inspector)
	{
		errstr = "No inspector provided yet";
		ret = NULL;
		return ret;
	}

	ret->set_extra(m_config.output_format, m_config.replace_container_info);
	ret->set_min_priority(m_config.min_priority);

	// Create "factories" that can create filters/formatters for
	// each supported source.
	for(const auto &source : m_config.event_sources)
	{
		std::shared_ptr<gen_event_filter_factory> filter_factory;
		std::shared_ptr<gen_event_formatter_factory> formatter_factory;

		if(source == syscall_source)
		{
			// This use of m_inspector looks unsafe, as it
			// may have been created on a different thread
			// than the thread where create_new() was
			// called. But the inspector is only *used*
			// when evaluating filters, and that is only
			// done on the thread processing events and
			// calling engine().
			filter_factory.reset(new sinsp_filter_factory(m_inspector));
			formatter_factory.reset(new sinsp_evt_formatter_factory(m_inspector));
		}
		else if (source == k8s_audit_source)
		{
			filter_factory.reset(new json_event_filter_factory());
			formatter_factory.reset(new json_event_formatter_factory(filter_factory));
		}
		else
		{
			// Assumed to be a source plugin
			filter_factory.reset(new sinsp_filter_factory(m_inspector, m_plugin_filter_checks));
			formatter_factory.reset(new sinsp_evt_formatter_factory(m_inspector, m_plugin_filter_checks));
		}

		if(m_config.json_output)
		{
			formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
		}

		ret->add_source(source, filter_factory, formatter_factory);
	}

	for(auto &rf : rulesfiles)
	{
		// XXX/mstemm verbose and all_events are actually unused, remove them.
		bool verbose = false;
		bool all_events = false;

		uint64_t required;

		try {
			ret->load_rules(rf.content, verbose, all_events, required);
		}
		catch(falco_exception &e)
		{
			errstr  = "Could not load rules file " + rf.name + ": " + e.what();
			ret = NULL;
			return ret;
		}
	}

	// Ensure that all plugins are compatible with the loaded set of rules
	for(auto &info : m_config.plugin_infos)
	{
		std::string required_version;

		if(!ret->is_plugin_compatible(info.name, info.plugin_version.as_string(), required_version))
		{
			errstr = std::string("Plugin ") + info.name + " version " + info.plugin_version.as_string() + " not compatible with required plugin version " + required_version;
			ret = NULL;
			return ret;
		}
	}

	for (auto substring : m_config.disabled_rule_substrings)
	{
		falco_logger::log(LOG_INFO, "Disabling rules matching substring: " + substring + "\n");
		ret->enable_rule(substring, false);
	}

	if(m_config.disabled_rule_tags.size() > 0)
	{
		for(auto tag : m_config.disabled_rule_tags)
		{
			falco_logger::log(LOG_INFO, "Disabling rules with tag: " + tag + "\n");
		}
		ret->enable_rule_by_tag(m_config.disabled_rule_tags, false);
	}

	if(m_config.enabled_rule_tags.size() > 0)
	{
		string all_rules = "";

		// Since we only want to enable specific
		// rules, first disable all rules.
		ret->enable_rule(all_rules, false);
		for(auto tag : m_config.enabled_rule_tags)
		{
			falco_logger::log(LOG_INFO, "Enabling rules with tag: " + tag + "\n");
		}
		ret->enable_rule_by_tag(m_config.enabled_rule_tags, true);
	}

	return ret;
}
