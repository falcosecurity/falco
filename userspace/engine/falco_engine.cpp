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

#include "formats.h"

extern "C" {
#include "lpeg.h"
#include "lyaml.h"
}

#include "utils.h"
#include "banned.h" // This raises a compilation error when certain functions are used


string lua_on_event = "on_event";
string lua_print_stats = "print_stats";
const std::string falco_engine::s_default_ruleset = "falco-default-ruleset";

using namespace std;

falco_engine::falco_engine(bool seed_rng)
	: m_next_ruleset_id(0),
	  m_min_priority(falco_common::PRIORITY_DEBUG),
	  m_sampling_ratio(1), m_sampling_multiplier(0),
	  m_replace_container_info(false)
{
	luaopen_yaml(m_ls);

	falco_common::init();
	falco_rules::init(m_ls);

	m_required_plugin_versions.clear();

	if(seed_rng)
	{
		srandom((unsigned) getpid());
	}

	m_default_ruleset_id = find_ruleset_id(s_default_ruleset);
}

falco_engine::~falco_engine()
{
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
	if(!m_rules)
	{
		m_rules.reset(new falco_rules(this,
					      m_ls));

		for(auto const &it : m_filter_factories)
		{
			m_rules->add_filter_factory(it.first, it.second);
		}
	}

	m_rules->load_rules(rules_content, verbose, all_events, m_extra, m_replace_container_info, m_min_priority, required_engine_version, m_required_plugin_versions);
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
		it.second->enable(substring, match_exact, enabled, ruleset_id);
	}
}

void falco_engine::enable_rule_exact(const string &rule_name, bool enabled, const string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);
	bool match_exact = true;

	for(auto &it : m_rulesets)
	{
		it.second->enable(rule_name, match_exact, enabled, ruleset_id);
	}
}

void falco_engine::enable_rule_by_tag(const set<string> &tags, bool enabled, const string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	for(auto &it : m_rulesets)
	{
		it.second->enable_tags(tags, enabled, ruleset_id);
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
		ret += it.second->num_rules_for_ruleset(ruleset_id);
	}

	return ret;
}

void falco_engine::evttypes_for_ruleset(std::string &source, std::set<uint16_t> &evttypes, const std::string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	auto it = m_rulesets.find(source);
	if(it == m_rulesets.end())
	{
		string err = "Unknown event source " + source;
		throw falco_exception(err);
	}

	it->second->evttypes_for_ruleset(evttypes, ruleset_id);

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

unique_ptr<falco_engine::rule_result> falco_engine::process_event(std::string &source, gen_event *ev, uint16_t ruleset_id)
{
	if(should_drop_evt())
	{
		return unique_ptr<struct rule_result>();
	}

	auto it = m_rulesets.find(source);
	if(it == m_rulesets.end())
	{
		string err = "Unknown event source " + source;
		throw falco_exception(err);
	}

	if (!it->second->run(ev, ruleset_id))
	{
		return unique_ptr<struct rule_result>();
	}

	unique_ptr<struct rule_result> res(new rule_result());
	res->source = source;

	populate_rule_result(res, ev);

	return res;
}

unique_ptr<falco_engine::rule_result> falco_engine::process_event(std::string &source, gen_event *ev)
{
	return process_event(source, ev, m_default_ruleset_id);
}

void falco_engine::add_source(const std::string &source,
			      std::shared_ptr<gen_event_filter_factory> filter_factory,
			      std::shared_ptr<gen_event_formatter_factory> formatter_factory)
{
	m_filter_factories[source] = filter_factory;
	m_format_factories[source] = formatter_factory;

	std::shared_ptr<falco_ruleset> ruleset(new falco_ruleset());
	m_rulesets[source] = ruleset;
}

void falco_engine::populate_rule_result(unique_ptr<struct rule_result> &res, gen_event *ev)
{
	std::lock_guard<std::mutex> guard(m_ls_semaphore);
	lua_getglobal(m_ls, lua_on_event.c_str());
	if(lua_isfunction(m_ls, -1))
	{
		lua_pushnumber(m_ls, ev->get_check_id());
		if(lua_pcall(m_ls, 1, 5, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error invoking function output: " + string(lerr);
			throw falco_exception(err);
		}
		const char *p =  lua_tostring(m_ls, -5);
		res->rule = p;
		res->evt = ev;
		res->priority_num = (falco_common::priority_type) lua_tonumber(m_ls, -4);
		res->format = lua_tostring(m_ls, -3);

		// Tags are passed back as a table, and is on the top of the stack
		lua_pushnil(m_ls);  /* first key */
		while (lua_next(m_ls, -2) != 0) {
			// key is at index -2, value is at index
			// -1. We want the value.
			res->tags.insert(luaL_checkstring(m_ls, -1));

			// Remove value, keep key for next iteration
			lua_pop(m_ls, 1);
		}
		lua_pop(m_ls, 1); // Clean table leftover

		// Exception fields are passed back as a table
		lua_pushnil(m_ls);  /* first key */
		while (lua_next(m_ls, -2) != 0) {
			// key is at index -2, value is at index
			// -1. We want the keys.
			res->exception_fields.insert(luaL_checkstring(m_ls, -2));

			// Remove value, keep key for next iteration
			lua_pop(m_ls, 1);
		}

		lua_pop(m_ls, 4);
	}
	else
	{
		throw falco_exception("No function " + lua_on_event + " found in lua compiler module");
	}
}

void falco_engine::describe_rule(string *rule)
{
	return m_rules->describe_rule(rule);
}

// Print statistics on the rules that triggered
void falco_engine::print_stats()
{
	lua_getglobal(m_ls, lua_print_stats.c_str());

	if(lua_isfunction(m_ls, -1))
	{
		if(lua_pcall(m_ls, 0, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error invoking function print_stats: " + string(lerr);
			throw falco_exception(err);
		}
	}
	else
	{
		throw falco_exception("No function " + lua_print_stats + " found in lua rule loader module");
	}

}

void falco_engine::add_filter(std::shared_ptr<gen_event_filter> filter,
			      std::string &rule,
			      std::string &source,
			      std::set<std::string> &tags)
{
	auto it = m_rulesets.find(source);
	if(it == m_rulesets.end())
	{
		string err = "Unknown event source " + source;
		throw falco_exception(err);
	}

	it->second->add(source, rule, tags, filter);
}

bool falco_engine::is_source_valid(const std::string &source)
{
	return (m_rulesets.find(source) != m_rulesets.end());
}

bool falco_engine::is_plugin_compatible(const std::string &name,
					const std::string &version,
					std::string &required_version)
{
	sinsp_plugin::version plugin_version(version);

	if(!plugin_version.m_valid)
	{
		throw falco_exception(string("Plugin version string ") + version + " not valid");
	}

	if(m_required_plugin_versions.find(name) == m_required_plugin_versions.end())
	{
		// No required engine versions, so no restrictions. Compatible.
		return true;
	}

	for(auto &rversion : m_required_plugin_versions[name])
	{
		sinsp_plugin::version req_version(rversion);
		if (!plugin_version.check(req_version))
		{
			required_version = rversion;
			return false;
		}
	}

	return true;
}

void falco_engine::clear_filters()
{
	m_rulesets.clear();

	for(auto &it : m_filter_factories)
	{
		std::shared_ptr<falco_ruleset> ruleset(new falco_ruleset());
		m_rulesets[it.first] = ruleset;
	}

	m_required_plugin_versions.clear();
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
