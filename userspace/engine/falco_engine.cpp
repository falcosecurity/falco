/*
Copyright (C) 2016-2018 Draios Inc dba Sysdig.

This file is part of falco.

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

#include "falco_engine.h"
#include "config_falco_engine.h"

#include "formats.h"

extern "C" {
#include "lpeg.h"
#include "lyaml.h"
}

#include "utils.h"


string lua_on_event = "on_event";
string lua_print_stats = "print_stats";

using namespace std;

falco_engine::falco_engine(bool seed_rng, const std::string& source_dir)
	: m_rules(NULL), m_next_ruleset_id(0),
	  m_min_priority(falco_common::PRIORITY_DEBUG),
	  m_sampling_ratio(1), m_sampling_multiplier(0),
	  m_replace_container_info(false)
{
	luaopen_lpeg(m_ls);
	luaopen_yaml(m_ls);

	falco_common::init(m_lua_main_filename.c_str(), source_dir.c_str());
	falco_rules::init(m_ls);

	m_evttype_filter.reset(new sinsp_evttype_filter());

	if(seed_rng)
	{
		srandom((unsigned) getpid());
	}

	m_default_ruleset_id = find_ruleset_id(m_default_ruleset);
}

falco_engine::~falco_engine()
{
	if (m_rules)
	{
		delete m_rules;
	}
}

void falco_engine::load_rules(const string &rules_content, bool verbose, bool all_events)
{
	// The engine must have been given an inspector by now.
	if(! m_inspector)
	{
		throw falco_exception("No inspector provided");
	}

	if(!m_rules)
	{
		m_rules = new falco_rules(m_inspector, this, m_ls);
	}

	// Note that falco_formats is added to both the lua state used
	// by the falco engine as well as the separate lua state used
	// by falco outputs.  Within the engine, only
	// formats.formatter is used, so we can unconditionally set
	// json_output to false.
	bool json_output = false;
	bool json_include_output_property = false;
	falco_formats::init(m_inspector, m_ls, json_output, json_include_output_property);

	m_rules->load_rules(rules_content, verbose, all_events, m_extra, m_replace_container_info, m_min_priority);
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

void falco_engine::enable_rule(const string &pattern, bool enabled, const string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	m_evttype_filter->enable(pattern, enabled, ruleset_id);
}

void falco_engine::enable_rule(const string &pattern, bool enabled)
{
	enable_rule(pattern, enabled, m_default_ruleset);
}

void falco_engine::enable_rule_by_tag(const set<string> &tags, bool enabled, const string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	m_evttype_filter->enable_tags(tags, enabled, ruleset_id);
}

void falco_engine::enable_rule_by_tag(const set<string> &tags, bool enabled)
{
	enable_rule_by_tag(tags, enabled, m_default_ruleset);
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

void falco_engine::evttypes_for_ruleset(std::vector<bool> &evttypes, const std::string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	return m_evttype_filter->evttypes_for_ruleset(evttypes, ruleset_id);
}

void falco_engine::syscalls_for_ruleset(std::vector<bool> &syscalls, const std::string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	return m_evttype_filter->syscalls_for_ruleset(syscalls, ruleset_id);
}

unique_ptr<falco_engine::rule_result> falco_engine::process_event(sinsp_evt *ev, uint16_t ruleset_id)
{
	if(should_drop_evt())
	{
		return unique_ptr<struct rule_result>();
	}

	if(!m_evttype_filter->run(ev, ruleset_id))
	{
		return unique_ptr<struct rule_result>();
	}

	unique_ptr<struct rule_result> res(new rule_result());

	lua_getglobal(m_ls, lua_on_event.c_str());

	if(lua_isfunction(m_ls, -1))
	{
		lua_pushlightuserdata(m_ls, ev);
		lua_pushnumber(m_ls, ev->get_check_id());

		if(lua_pcall(m_ls, 2, 3, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error invoking function output: " + string(lerr);
			throw falco_exception(err);
		}
		res->evt = ev;
		const char *p =  lua_tostring(m_ls, -3);
		res->rule = p;
		res->priority_num = (falco_common::priority_type) lua_tonumber(m_ls, -2);
		res->format = lua_tostring(m_ls, -1);
		lua_pop(m_ls, 3);
	}
	else
	{
		throw falco_exception("No function " + lua_on_event + " found in lua compiler module");
	}

	return res;
}

unique_ptr<falco_engine::rule_result> falco_engine::process_event(sinsp_evt *ev)
{
	return process_event(ev, m_default_ruleset_id);
}

void falco_engine::describe_rule(string *rule)
{
	return m_rules->describe_rule(rule);
}

// Print statistics on the the rules that triggered
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

void falco_engine::add_evttype_filter(string &rule,
				      set<uint32_t> &evttypes,
				      set<uint32_t> &syscalls,
				      set<string> &tags,
				      sinsp_filter* filter)
{
	m_evttype_filter->add(rule, evttypes, syscalls, tags, filter);
}

void falco_engine::clear_filters()
{
	m_evttype_filter.reset(new sinsp_evttype_filter());
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
