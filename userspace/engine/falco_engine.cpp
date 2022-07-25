/*
Copyright (C) 2019 The Falco Authors.

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

#include <cstdlib>
#include <unistd.h>
#include <string>
#include <fstream>

#include <sinsp.h>
#include <plugin.h>

#include "falco_engine.h"
#include "falco_utils.h"
#include "falco_engine_version.h"
#include "rule_reader.h"

#include "formats.h"

#include "utils.h"
#include "banned.h" // This raises a compilation error when certain functions are used
#include "evttype_index_ruleset.h"

const std::string falco_engine::s_default_ruleset = "falco-default-ruleset";

using namespace std;

falco_engine::falco_engine(bool seed_rng)
	: m_next_ruleset_id(0),
	  m_min_priority(falco_common::PRIORITY_DEBUG),
	  m_sampling_ratio(1), m_sampling_multiplier(0),
	  m_replace_container_info(false)
{
	if(seed_rng)
	{
		srandom((unsigned) getpid());
	}

	m_default_ruleset_id = find_ruleset_id(s_default_ruleset);
}

falco_engine::~falco_engine()
{
	m_rules.clear();
	m_rule_loader.clear();
	m_rule_stats_manager.clear();
	m_sources.clear();
}

uint32_t falco_engine::engine_version()
{
	return (uint32_t) FALCO_ENGINE_VERSION;
}

falco_source* falco_engine::find_source(const std::string& name)
{
	auto ret = m_sources.at(name);
	if(!ret)
	{
		throw falco_exception("Unknown event source " + name);
	}
	return ret;
}

falco_source* falco_engine::find_source(std::size_t index)
{
	auto ret = m_sources.at(index);
	if(!ret)
	{
		throw falco_exception("Unknown event source index " + to_string(index));
	}
	return ret;
}

// Return a key that uniquely represents a field class.
// For now, we assume name + shortdesc is unique.
static std::string fieldclass_key(const gen_event_filter_factory::filter_fieldclass_info &fld_info)
{
	return fld_info.name + fld_info.shortdesc;
}

void falco_engine::list_fields(std::string &source, bool verbose, bool names_only, bool markdown)
{
	// Maps from field class name + short desc to list of event
	// sources for which this field class can be used.
	std::map<std::string,std::set<std::string>> fieldclass_event_sources;

	// Do a first pass to group together classes that are
	// applicable to multiple event sources.
	for(auto &it : m_sources)
	{
		if(source != "" && source != it.name)
		{
			continue;
		}

		for(auto &fld_class : it.filter_factory->get_fields())
		{
			fieldclass_event_sources[fieldclass_key(fld_class)].insert(it.name);
		}
	}

	// The set of field classes already printed. Used to avoid
	// printing field classes multiple times for different sources
	std::set<std::string> seen_fieldclasses;

	// In the second pass, actually print info, skipping duplicate
	// field classes and also printing info on supported sources.
	for(auto &it : m_sources)
	{
		if(source != "" && source != it.name)
		{
			continue;
		}

		for(auto &fld_class : it.filter_factory->get_fields())
		{
			std::string key = fieldclass_key(fld_class);

			if(seen_fieldclasses.find(key) != seen_fieldclasses.end())
			{
				continue;
			}

			seen_fieldclasses.insert(key);

			if(names_only)
			{
				for(auto &field : fld_class.fields)
				{
					// Skip fields with the EPF_TABLE_ONLY flag.
					if(field.tags.find("EPF_TABLE_ONLY") != field.tags.end())
					{
						continue;
					}

					printf("%s\n", field.name.c_str());
				}
			}
			else if (markdown)
			{
				printf("%s\n", fld_class.as_markdown(
									fieldclass_event_sources[fieldclass_key(fld_class)]).c_str());
			}
			else
			{
				printf("%s\n", fld_class.as_string(verbose,
								   fieldclass_event_sources[fieldclass_key(fld_class)]).c_str());
			}
		}
	}
}

void falco_engine::load_rules(const string &rules_content, bool verbose, bool all_events)
{
	rule_loader::configuration cfg(rules_content, m_sources);
	cfg.min_priority = m_min_priority;
	cfg.output_extra = m_extra;
	cfg.replace_output_container_info = m_replace_container_info;
	cfg.default_ruleset_id = m_default_ruleset_id;

	std::ostringstream os;
	rule_reader reader;
	bool success = reader.load(cfg, m_rule_loader);
	if (success)
	{
		for (auto &src : m_sources)
		{
			src.ruleset = src.ruleset_factory->new_ruleset();
		}
		m_rules.clear();
		success = m_rule_loader.compile(cfg, m_rules);
	}
	if (!cfg.errors.empty())
	{
		os << cfg.errors.size() << " errors:" << std::endl;
		for(auto &err : cfg.errors)
		{
			os << err << std::endl;
		}
	}
	if (!cfg.warnings.empty())
	{
		os << cfg.warnings.size() << " warnings:" << std::endl;
		for(auto &warn : cfg.warnings)
		{
			os << warn << std::endl;
		}
	}
	if(!success)
	{
		throw falco_exception(os.str());
	}
	if (verbose && os.str() != "") {
		// todo(jasondellaluce): introduce a logging callback in Falco
		fprintf(stderr, "When reading rules content: %s", os.str().c_str());
	}
}

void falco_engine::load_rules_file(const string &rules_filename, bool verbose, bool all_events)
{
	ifstream is;

	is.open(rules_filename);
	if (!is.is_open())
	{
		throw falco_exception("Could not open rules filename " +
				      rules_filename + " " +
				      "for reading");
	}

	string rules_content((istreambuf_iterator<char>(is)),
			     istreambuf_iterator<char>());

	load_rules(rules_content, verbose, all_events);
}

void falco_engine::enable_rule(const string &substring, bool enabled, const string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);
	bool match_exact = false;

	for(auto &it : m_sources)
	{
		if(enabled)
		{
			it.ruleset->enable(substring, match_exact, ruleset_id);
		}
		else
		{
			it.ruleset->disable(substring, match_exact, ruleset_id);
		}
	}
}

void falco_engine::enable_rule_exact(const string &rule_name, bool enabled, const string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);
	bool match_exact = true;

	for(auto &it : m_sources)
	{
		if(enabled)
		{
			it.ruleset->enable(rule_name, match_exact, ruleset_id);
		}
		else
		{
			it.ruleset->disable(rule_name, match_exact, ruleset_id);
		}
	}
}

void falco_engine::enable_rule_by_tag(const set<string> &tags, bool enabled, const string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	for(auto &it : m_sources)
	{
		if(enabled)
		{
			it.ruleset->enable_tags(tags, ruleset_id);
		}
		else
		{
			it.ruleset->disable_tags(tags, ruleset_id);
		}
	}
}

void falco_engine::set_min_priority(falco_common::priority_type priority)
{
	m_min_priority = priority;
}

uint16_t falco_engine::find_ruleset_id(const std::string &ruleset)
{
	auto it = m_known_rulesets.lower_bound(ruleset);
	if(it == m_known_rulesets.end() || it->first != ruleset)
	{
		it = m_known_rulesets.emplace_hint(it,
						   std::make_pair(ruleset, m_next_ruleset_id++));
	}
	return it->second;
}

uint64_t falco_engine::num_rules_for_ruleset(const std::string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);
	uint64_t ret = 0;
	for (auto &src : m_sources)
	{
		ret += src.ruleset->enabled_count(ruleset_id);
	}
	return ret;
}

void falco_engine::evttypes_for_ruleset(std::string &source, std::set<uint16_t> &evttypes, const std::string &ruleset)
{
	find_source(source)->ruleset->enabled_evttypes(evttypes, find_ruleset_id(ruleset));
}

std::shared_ptr<gen_event_formatter> falco_engine::create_formatter(const std::string &source,
								    const std::string &output)
{
	return find_source(source)->formatter_factory->create_formatter(output);
}

unique_ptr<falco_engine::rule_result> falco_engine::process_event(std::size_t source_idx, gen_event *ev, uint16_t ruleset_id)
{
	falco_rule rule;
	if(should_drop_evt() || !find_source(source_idx)->ruleset->run(ev, rule, ruleset_id))
	{
		return unique_ptr<struct rule_result>();
	}

	unique_ptr<struct rule_result> res(new rule_result());
	res->evt = ev;
	res->rule = rule.name;
	res->source = rule.source;
	res->format = rule.output;
	res->priority_num = rule.priority;
	res->tags = rule.tags;
	res->exception_fields = rule.exception_fields;
	m_rule_stats_manager.on_event(rule);
	return res;
}

unique_ptr<falco_engine::rule_result> falco_engine::process_event(std::size_t source_idx, gen_event *ev)
{
	return process_event(source_idx, ev, m_default_ruleset_id);
}

std::size_t falco_engine::add_source(const std::string &source,
				     std::shared_ptr<gen_event_filter_factory> filter_factory,
				     std::shared_ptr<gen_event_formatter_factory> formatter_factory)
{
	// evttype_index_ruleset is the default ruleset implementation
	std::shared_ptr<filter_ruleset_factory> ruleset_factory(
		new evttype_index_ruleset_factory(filter_factory));
	return add_source(source, filter_factory, formatter_factory, ruleset_factory);
}

std::size_t falco_engine::add_source(const std::string &source,
	std::shared_ptr<gen_event_filter_factory> filter_factory,
	std::shared_ptr<gen_event_formatter_factory> formatter_factory,
	std::shared_ptr<filter_ruleset_factory> ruleset_factory)
{
	falco_source src;
	src.name = source;
	src.filter_factory = filter_factory;
	src.formatter_factory = formatter_factory;
	src.ruleset_factory = ruleset_factory;
	src.ruleset = ruleset_factory->new_ruleset();
	return m_sources.insert(src, source);
}

void falco_engine::describe_rule(string *rule)
{
	static const char* rule_fmt = "%-50s %s\n";
	fprintf(stdout, rule_fmt, "Rule", "Description");
	fprintf(stdout, rule_fmt, "----",  "-----------");
	if (!rule)
	{
		for (auto &r : m_rules)
		{
			auto str = falco::utils::wrap_text(r.description, 51, 110) + "\n";
			fprintf(stdout, rule_fmt, r.name.c_str(), str.c_str());
		}
	}
	else
	{
		auto r = m_rules.at(*rule);
		auto str = falco::utils::wrap_text(r->description, 51, 110) + "\n";
		fprintf(stdout, rule_fmt, r->name.c_str(), str.c_str());
	}
}

void falco_engine::print_stats()
{
	string out;
	m_rule_stats_manager.format(m_rules, out);
	// todo(jasondellaluce): introduce a logging callback in Falco
	fprintf(stdout, "%s", out.c_str());
}

bool falco_engine::is_source_valid(const std::string &source)
{
	return m_sources.at(source) != nullptr;
}

bool falco_engine::check_plugin_requirements(
		const std::vector<plugin_version_requirement>& plugins,
		std::string& err)
{
	for (const auto &req : m_rule_loader.required_plugin_versions())
	{
		bool found = false;
		for (const auto &plugin : plugins)
		{
			if (req.first == plugin.name)
			{
				found = true;
				sinsp_version plugin_version(plugin.version);
				if(!plugin_version.m_valid)
				{
					err = "Plugin '" + req.first
						+ "' has invalid version string '"
						+ plugin.version + "'";
					return false;
				}
				for (const auto &reqver: req.second)
				{
					sinsp_version req_version(reqver);
					if (!plugin_version.check(req_version))
					{
						err = "Plugin '" + plugin.name
						+ "' version '" + plugin.version
						+ "' is not compatible with required plugin version '"
						+ reqver + "'";
						return false;
					}
				}
			}
		}
		if (!found)
		{
			err = "Plugin '" + req.first + "' is required but not loaded";
			return false;
		}
	}
	return true;
}

void falco_engine::complete_rule_loading()
{
	for (auto &src : m_sources)
	{
		src.ruleset->on_loading_complete();
	}
}

void falco_engine::set_sampling_ratio(uint32_t sampling_ratio)
{
	m_sampling_ratio = sampling_ratio;
}

void falco_engine::set_sampling_multiplier(double sampling_multiplier)
{
	m_sampling_multiplier = sampling_multiplier;
}

void falco_engine::set_extra(string &extra, bool replace_container_info)
{
	m_extra = extra;
	m_replace_container_info = replace_container_info;
}

inline bool falco_engine::should_drop_evt()
{
	if(m_sampling_multiplier == 0)
	{
		return false;
	}

	if(m_sampling_ratio == 1)
	{
		return false;
	}

	double coin = (random() * (1.0/RAND_MAX));
	return (coin >= (1.0/(m_sampling_multiplier * m_sampling_ratio)));
}
