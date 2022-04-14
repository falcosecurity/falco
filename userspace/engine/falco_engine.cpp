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
}

uint32_t falco_engine::engine_version()
{
	return (uint32_t) FALCO_ENGINE_VERSION;
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
	for(auto &it : m_filter_factories)
	{
		if(source != "" && source != it.first)
		{
			continue;
		}

		for(auto &fld_class : it.second->get_fields())
		{
			fieldclass_event_sources[fieldclass_key(fld_class)].insert(it.first);
		}
	}

	// The set of field classes already printed. Used to avoid
	// printing field classes multiple times for different sources
	std::set<std::string> seen_fieldclasses;

	// In the second pass, actually print info, skipping duplicate
	// field classes and also printing info on supported sources.
	for(auto &it : m_filter_factories)
	{
		if(source != "" && source != it.first)
		{
			continue;
		}

		for(auto &fld_class : it.second->get_fields())
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
	uint64_t dummy;

	return load_rules(rules_content, verbose, all_events, dummy);
}

void falco_engine::load_rules(const string &rules_content, bool verbose, bool all_events, uint64_t &required_engine_version)
{
	rule_loader::context ctx(rules_content);
	ctx.engine = this;
	ctx.min_priority = m_min_priority;
	ctx.output_extra = m_extra;
	ctx.replace_output_container_info = m_replace_container_info;

	std::ostringstream os;
	rule_reader reader;
	bool success = reader.load(ctx, m_rule_loader);
	if (success)
	{
		clear_filters();
		m_rules.clear();
		success = m_rule_loader.compile(ctx, m_rules);
	}
	if (!ctx.errors.empty())
	{
		os << ctx.errors.size() << " errors:" << std::endl;
		for(auto &err : ctx.errors)
		{
			os << err << std::endl;
		}
	}
	if (!ctx.warnings.empty())
	{
		os << ctx.warnings.size() << " warnings:" << std::endl;
		for(auto &warn : ctx.warnings)
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
	uint64_t dummy;

	return load_rules_file(rules_filename, verbose, all_events, dummy);
}

void falco_engine::load_rules_file(const string &rules_filename, bool verbose, bool all_events, uint64_t &required_engine_version)
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

	load_rules(rules_content, verbose, all_events, required_engine_version);
}

void falco_engine::enable_rule(const string &substring, bool enabled, const string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);
	bool match_exact = false;

	for(auto &it : m_rulesets)
	{
		it.ruleset->enable(substring, match_exact, enabled, ruleset_id);
	}
}

void falco_engine::enable_rule_exact(const string &rule_name, bool enabled, const string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);
	bool match_exact = true;

	for(auto &it : m_rulesets)
	{
		it.ruleset->enable(rule_name, match_exact, enabled, ruleset_id);
	}
}

void falco_engine::enable_rule_by_tag(const set<string> &tags, bool enabled, const string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	for(auto &it : m_rulesets)
	{
		it.ruleset->enable_tags(tags, enabled, ruleset_id);
	}
}

void falco_engine::set_min_priority(falco_common::priority_type priority)
{
	m_min_priority = priority;
}

uint16_t falco_engine::find_ruleset_id(const std::string &ruleset)
{
	auto it = m_known_rulesets.lower_bound(ruleset);

	if(it == m_known_rulesets.end() ||
	   it->first != ruleset)
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
	for(auto &it : m_rulesets)
	{
		ret += it.ruleset->num_rules_for_ruleset(ruleset_id);
	}

	return ret;
}

void falco_engine::evttypes_for_ruleset(std::string &source, std::set<uint16_t> &evttypes, const std::string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	auto it = find_ruleset(source);
	if(it == m_rulesets.end())
	{
		string err = "Unknown event source " + source;
		throw falco_exception(err);
	}

	it->ruleset->evttypes_for_ruleset(evttypes, ruleset_id);

}

std::shared_ptr<gen_event_formatter> falco_engine::create_formatter(const std::string &source,
								    const std::string &output)
{
	auto it = m_format_factories.find(source);

	if(it == m_format_factories.end())
	{
		string err = "Unknown event source " + source;
		throw falco_exception(err);
	}

	return it->second->create_formatter(output);
}

unique_ptr<falco_engine::rule_result> falco_engine::process_event(std::size_t source_idx, gen_event *ev, uint16_t ruleset_id)
{
	if(should_drop_evt())
	{
		return unique_ptr<struct rule_result>();
	}

	try
	{
		auto &r = m_rulesets.at(source_idx);
		if(!r.ruleset->run(ev, ruleset_id))
		{
			return unique_ptr<struct rule_result>();
		}

		unique_ptr<struct rule_result> res(new rule_result());
		// note: indexes are 0-based, whereas check_ids are not
		auto rule_idx = ev->get_check_id() - 1;
		auto rule = m_rules.at(rule_idx);
		if (!rule)
		{
			throw falco_exception("populate_rule_result error: unknown rule id "
					+ to_string(rule_idx));
		}
		res->evt = ev;
		res->rule = rule->name;
		res->source = rule->source;
		res->format = rule->output;
		res->priority_num = rule->priority;
		res->tags = rule->tags;
		res->exception_fields = rule->exception_fields;
		m_rule_stats_manager.on_event(m_rules, rule_idx);
		return res;
	}
	catch(std::out_of_range const &exc)
	{
		std::string err = "Unknown event source index " + std::to_string(source_idx);
		throw falco_exception(err);
	}
}

unique_ptr<falco_engine::rule_result> falco_engine::process_event(std::size_t source_idx, gen_event *ev)
{
	return process_event(source_idx, ev, m_default_ruleset_id);
}

std::size_t falco_engine::add_source(const std::string &source,
				     std::shared_ptr<gen_event_filter_factory> filter_factory,
				     std::shared_ptr<gen_event_formatter_factory> formatter_factory)
{
	m_filter_factories[source] = filter_factory;
	m_format_factories[source] = formatter_factory;

	auto idx = m_rulesets.size();
	m_rulesets.emplace_back(source, new falco_ruleset);
	// here we just trust the caller they won't add the same source more than once
	return idx;
}

std::shared_ptr<gen_event_filter_factory> falco_engine::get_filter_factory(
	const std::string &source)
{
	auto it = m_filter_factories.find(source);
	if(it == m_filter_factories.end())
	{
		throw falco_exception(string("unknown event source: ") + source);
	}
	return it->second;
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

void falco_engine::add_filter(std::shared_ptr<gen_event_filter> filter,
			      std::string &rule,
			      std::string &source,
			      std::set<std::string> &tags)
{
	auto it = find_ruleset(source);
	if(it == m_rulesets.end())
	{
		string err = "Unknown event source " + source;
		throw falco_exception(err);
	}

	it->ruleset->add(source, rule, tags, filter);
}

bool falco_engine::is_source_valid(const std::string &source)
{
	return (find_ruleset(source) != m_rulesets.end());
}

bool falco_engine::is_plugin_compatible(const std::string &name,
					const std::string &version,
					std::string &required_version)
{
	return m_rule_loader.is_plugin_compatible(name, version, required_version);
}

void falco_engine::clear_filters()
{
	for(auto &it : m_rulesets)
	{
		it.ruleset.reset(new falco_ruleset);
	}
}

void falco_engine::clear_loader()
{
	m_rule_loader.clear();
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

inline std::vector<falco_engine::ruleset_node>::iterator falco_engine::find_ruleset(const std::string &source)
{
	return std::find_if(
		m_rulesets.begin(), m_rulesets.end(),
		[&source](const ruleset_node &r) { return r.source == source; });
}

inline std::vector<falco_engine::ruleset_node>::const_iterator falco_engine::find_ruleset(const std::string &source) const
{
	return std::find_if(
		m_rulesets.cbegin(), m_rulesets.cend(),
		[&source](const ruleset_node &r) { return r.source == source; });
}
