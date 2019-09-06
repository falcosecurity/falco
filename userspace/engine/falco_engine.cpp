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
#include "falco_engine_version.h"
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

nlohmann::json::json_pointer falco_engine::k8s_audit_time = "/stageTimestamp"_json_pointer;

falco_engine::falco_engine(bool seed_rng, const std::string& alternate_lua_dir)
	: m_rules(NULL), m_next_ruleset_id(0),
	  m_min_priority(falco_common::PRIORITY_DEBUG),
	  m_sampling_ratio(1), m_sampling_multiplier(0),
	  m_replace_container_info(false)
{
	luaopen_lpeg(m_ls);
	luaopen_yaml(m_ls);

	falco_common::init(m_lua_main_filename.c_str(), alternate_lua_dir.c_str());
	falco_rules::init(m_ls);

	m_sinsp_rules.reset(new falco_sinsp_ruleset());
	m_k8s_audit_rules.reset(new falco_ruleset());

	if(seed_rng)
	{
		srandom((unsigned) getpid());
	}

	m_default_ruleset_id = find_ruleset_id(m_default_ruleset);

	// Create this now so we can potentially list filters and exit
	m_json_factory = make_shared<json_event_filter_factory>();
}

falco_engine::~falco_engine()
{
	if (m_rules)
	{
		delete m_rules;
	}
}

uint32_t falco_engine::engine_version()
{
	return (uint32_t) FALCO_ENGINE_VERSION;
}

#define DESCRIPTION_TEXT_START 16

#define CONSOLE_LINE_LEN 79

static void wrap_text(const std::string &str, uint32_t initial_pos, uint32_t indent, uint32_t line_len)
{
	size_t len = str.size();

	for(uint32_t l = 0; l < len; l++)
	{
		if(l % (line_len - indent) == 0 && l != 0)
		{
			printf("\n");

			for(uint32_t m = 0; m < indent; m++)
			{
				printf(" ");
			}
		}

		printf("%c", str.at(l));
	}

	printf("\n");
}

void falco_engine::list_fields(bool names_only)
{
	for(auto &chk_field : json_factory().get_fields())
	{
		if(!names_only)
		{
			printf("\n----------------------\n");
			printf("Field Class: %s (%s)\n\n", chk_field.m_name.c_str(), chk_field.m_desc.c_str());
			if(chk_field.m_class_info != "")
			{
				wrap_text(chk_field.m_class_info, 0, 0, CONSOLE_LINE_LEN);
				printf("\n");
			}
		}

		for(auto &field : chk_field.m_fields)
		{
			printf("%s", field.m_name.c_str());

			if(names_only)
			{
				printf("\n");
				continue;
			}
			uint32_t namelen = field.m_name.size();

			if(namelen >= DESCRIPTION_TEXT_START)
			{
				printf("\n");
				namelen = 0;
			}

			for(uint32_t l = 0; l < DESCRIPTION_TEXT_START - namelen; l++)
			{
				printf(" ");
			}

			std::string desc = field.m_desc;
			switch(field.m_idx_mode)
			{
			case json_event_filter_check::IDX_REQUIRED:
			case json_event_filter_check::IDX_ALLOWED:
				desc += " (";
				desc += json_event_filter_check::s_index_mode_strs[field.m_idx_mode];
				desc += ", ";
				desc += json_event_filter_check::s_index_type_strs[field.m_idx_type];
				desc += ")";
				break;
			case json_event_filter_check::IDX_NONE:
			default:
				break;
			};

			wrap_text(desc, namelen, DESCRIPTION_TEXT_START, CONSOLE_LINE_LEN);
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
	// The engine must have been given an inspector by now.
	if(! m_inspector)
	{
		throw falco_exception("No inspector provided");
	}

	if(!m_sinsp_factory)
	{
		m_sinsp_factory = make_shared<sinsp_filter_factory>(m_inspector);
	}

	if(!m_rules)
	{
		m_rules = new falco_rules(m_inspector,
					  this,
					  m_ls);
	}

	// Note that falco_formats is added to both the lua state used
	// by the falco engine as well as the separate lua state used
	// by falco outputs.  Within the engine, only
	// formats.formatter is used, so we can unconditionally set
	// json_output to false.
	bool json_output = false;
	bool json_include_output_property = false;
	falco_formats::init(m_inspector, this, m_ls, json_output, json_include_output_property);

	m_rules->load_rules(rules_content, verbose, all_events, m_extra, m_replace_container_info, m_min_priority, required_engine_version);
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

std::string falco_engine::k8s_psp_to_falco_rules(const std::string &psp_yaml, const std::string &rules_template)
{
	return m_psp_converter.generate_rules(psp_yaml, rules_template);
}

void falco_engine::enable_rule(const string &substring, bool enabled, const string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	m_sinsp_rules->enable(substring, enabled, ruleset_id);
	m_k8s_audit_rules->enable(substring, enabled, ruleset_id);
}

void falco_engine::enable_rule(const string &substring, bool enabled)
{
	enable_rule(substring, enabled, m_default_ruleset);
}

void falco_engine::enable_rule_by_tag(const set<string> &tags, bool enabled, const string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	m_sinsp_rules->enable_tags(tags, enabled, ruleset_id);
	m_k8s_audit_rules->enable_tags(tags, enabled, ruleset_id);
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

uint64_t falco_engine::num_rules_for_ruleset(const std::string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	return m_sinsp_rules->num_rules_for_ruleset(ruleset_id) +
		m_k8s_audit_rules->num_rules_for_ruleset(ruleset_id);
}

void falco_engine::evttypes_for_ruleset(std::vector<bool> &evttypes, const std::string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	return m_sinsp_rules->evttypes_for_ruleset(evttypes, ruleset_id);
}

void falco_engine::syscalls_for_ruleset(std::vector<bool> &syscalls, const std::string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	return m_sinsp_rules->syscalls_for_ruleset(syscalls, ruleset_id);
}

unique_ptr<falco_engine::rule_result> falco_engine::process_sinsp_event(sinsp_evt *ev, uint16_t ruleset_id)
{
	if(should_drop_evt())
	{
		return unique_ptr<struct rule_result>();
	}

	if(!m_sinsp_rules->run(ev, ruleset_id))
	{
		return unique_ptr<struct rule_result>();
	}

	unique_ptr<struct rule_result> res(new rule_result());

	lua_getglobal(m_ls, lua_on_event.c_str());

	if(lua_isfunction(m_ls, -1))
	{
		lua_pushnumber(m_ls, ev->get_check_id());

		if(lua_pcall(m_ls, 1, 3, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error invoking function output: " + string(lerr);
			throw falco_exception(err);
		}
		res->evt = ev;
		const char *p =  lua_tostring(m_ls, -3);
		res->rule = p;
		res->source = "syscall";
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

unique_ptr<falco_engine::rule_result> falco_engine::process_sinsp_event(sinsp_evt *ev)
{
	return process_sinsp_event(ev, m_default_ruleset_id);
}

unique_ptr<falco_engine::rule_result> falco_engine::process_k8s_audit_event(json_event *ev, uint16_t ruleset_id)
{
	if(should_drop_evt())
	{
		return unique_ptr<struct rule_result>();
	}

	// All k8s audit events have the single tag "1".
	if(!m_k8s_audit_rules->run((gen_event *) ev, 1, ruleset_id))
	{
		return unique_ptr<struct rule_result>();
	}

	unique_ptr<struct rule_result> res(new rule_result());

	lua_getglobal(m_ls, lua_on_event.c_str());

	if(lua_isfunction(m_ls, -1))
	{
		lua_pushnumber(m_ls, ev->get_check_id());

		if(lua_pcall(m_ls, 1, 3, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error invoking function output: " + string(lerr);
			throw falco_exception(err);
		}
		res->evt = ev;
		const char *p =  lua_tostring(m_ls, -3);
		res->rule = p;
		res->source = "k8s_audit";
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

bool falco_engine::parse_k8s_audit_json(nlohmann::json &j, std::list<json_event> &evts)
{
	// Note that nlohmann::basic_json::value can throw  nlohmann::basic_json::type_error (302, 306)
	try
	{
		// If the kind is EventList, split it into individual events
		if(j.value("kind", "<NA>") == "EventList")
		{
			for(auto &je : j["items"])
			{
				evts.emplace_back();
				je["kind"] = "Event";

				uint64_t ns = 0;
				if(!sinsp_utils::parse_iso_8601_utc_string(je.value(k8s_audit_time, "<NA>"), ns))
				{
					return false;
				}

				std::string tmp;
				sinsp_utils::ts_to_string(ns, &tmp, false, true);

				evts.back().set_jevt(je, ns);
			}

			return true;
		}
		else if(j.value("kind", "<NA>") == "Event")
		{
			evts.emplace_back();
			uint64_t ns = 0;
			if(!sinsp_utils::parse_iso_8601_utc_string(j.value(k8s_audit_time, "<NA>"), ns))
			{
				return false;
			}

			evts.back().set_jevt(j, ns);
			return true;
		}
		else
		{
			return false;
		}
	}
	catch(exception &e)
	{
		// Propagate the exception
		rethrow_exception(current_exception());
		return false;
	}
}

unique_ptr<falco_engine::rule_result> falco_engine::process_k8s_audit_event(json_event *ev)
{
	return process_k8s_audit_event(ev, m_default_ruleset_id);
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

void falco_engine::add_sinsp_filter(string &rule,
				    set<uint32_t> &evttypes,
				    set<uint32_t> &syscalls,
				    set<string> &tags,
				    sinsp_filter* filter)
{
	m_sinsp_rules->add(rule, evttypes, syscalls, tags, filter);
}

void falco_engine::add_k8s_audit_filter(string &rule,
					set<string> &tags,
					json_event_filter* filter)
{
	// All k8s audit events have a single tag "1".
	std::set<uint32_t> event_tags = {1};

	m_k8s_audit_rules->add(rule, tags, event_tags, filter);
}

void falco_engine::clear_filters()
{
	m_sinsp_rules.reset(new falco_sinsp_ruleset());
	m_k8s_audit_rules.reset(new falco_ruleset());
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

sinsp_filter_factory &falco_engine::sinsp_factory()
{
	if(!m_sinsp_factory)
	{
		throw falco_exception("No sinsp factory created yet");
	}

	return *(m_sinsp_factory.get());
}

json_event_filter_factory &falco_engine::json_factory()
{
	if(!m_json_factory)
	{
		throw falco_exception("No json factory created yet");
	}

	return *(m_json_factory.get());
}
