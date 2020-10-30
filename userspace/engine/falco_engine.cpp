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

#include "falco_engine.h"
#include "falco_utils.h"
#include "falco_engine_version.h"
#include "config_falco_engine.h"

#include "formats.h"

extern "C"
{
#include "lpeg.h"
#include "lyaml.h"
}

#include "utils.h"
#include "banned.h" // This raises a compilation error when certain functions are used

string lua_on_event = "on_event";
string lua_print_stats = "print_stats";

using namespace std;

nlohmann::json::json_pointer falco_engine::k8s_audit_time = "/stageTimestamp"_json_pointer;

falco_engine::falco_engine(bool seed_rng, const std::string &alternate_lua_dir):
	m_rules(NULL), m_next_ruleset_id(0),
	m_min_priority(falco_common::PRIORITY_DEBUG),
	m_sampling_ratio(1), m_sampling_multiplier(0),
	m_replace_container_info(false)
{
	luaopen_lpeg(m_ls);
	luaopen_yaml(m_ls);

	m_alternate_lua_dir = alternate_lua_dir;
	falco_common::init(m_lua_main_filename.c_str(), alternate_lua_dir.c_str());
	falco_rules::init(m_ls);

	clear_filters();

	if(seed_rng)
	{
		srandom((unsigned)getpid());
	}

	m_default_ruleset_id = find_ruleset_id(m_default_ruleset);

	// Create this now so we can potentially list filters and exit
	m_json_factory = make_shared<json_event_filter_factory>();
}

falco_engine::~falco_engine()
{
	if(m_rules)
	{
		delete m_rules;
	}
}

falco_engine *falco_engine::clone()
{
	auto engine = new falco_engine(true, m_alternate_lua_dir);
	engine->set_inspector(m_inspector);
	engine->set_extra(m_extra, m_replace_container_info);
	engine->set_min_priority(m_min_priority);
	return engine;
}

uint32_t falco_engine::engine_version()
{
	return (uint32_t)FALCO_ENGINE_VERSION;
}

#define DESCRIPTION_TEXT_START 16

#define CONSOLE_LINE_LEN 79

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
				std::string str = falco::utils::wrap_text(chk_field.m_class_info, 0, 0, CONSOLE_LINE_LEN);
				printf("%s\n", str.c_str());
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

			std::string str = falco::utils::wrap_text(desc, namelen, DESCRIPTION_TEXT_START, CONSOLE_LINE_LEN);
			printf("%s\n", str.c_str());
		}
	}
}

void falco_engine::load_rules_file(const string &rules_filename, bool verbose, bool all_events)
{
	ifstream is;

	is.open(rules_filename);
	if(!is.is_open())
	{
		throw falco_exception("Could not open rules filename " +
				      rules_filename + " " +
				      "for reading");
	}

	string rules_content((istreambuf_iterator<char>(is)),
			     istreambuf_iterator<char>());

	load_rules(rules_content, verbose, all_events);
}

void falco_engine::load_rules(const string &rules_content, bool verbose, bool all_events)
{
	// The engine must have been given an inspector by now.
	if(!m_inspector)
	{
		throw falco_exception("No inspector provided");
	}

	if(!m_sinsp_factory)
	{
		m_sinsp_factory = make_shared<sinsp_filter_factory>(m_inspector);
	}

	if(!m_rules)
	{
		// Note that falco_formats is added to the lua state used by the falco engine only.
		// Within the engine, only formats.
		// Formatter is used, so we can unconditionally set json_output to false.
		bool json_output = false;
		bool json_include_output_property = false;
		falco_formats::init(m_inspector, this, m_ls, json_output, json_include_output_property);
		m_rules = new falco_rules(m_inspector, this, m_ls);
	}

	uint64_t dummy;
	// m_sinsp_rules.reset(new falco_sinsp_ruleset());
	// m_k8s_audit_rules.reset(new falco_ruleset());
	m_rules->load_rules(rules_content, verbose, all_events, m_extra, m_replace_container_info, m_min_priority, dummy);

	m_is_ready = true;

	return;

	//
	// auto local_rules = new falco_rules(m_inspector, this, m_ls);
	// try
	// {
	// 	uint64_t dummy;
	// 	local_rules->load_rules(rules_content, verbose, all_events, m_extra, m_replace_container_info, m_min_priority, dummy);

	// 	// m_rules = local_rules
	// 	// std::atomic<falco_rules *> lore(m_rules);
	// 	// std::atomic_exchange(&lore, local_rules);
	// 	// SCHEDULE LOCAL_RULES AS NEXT RULESET
	// }
	// catch(const falco_exception &e)
	// {
	// 	// todo
	// 	printf("IGNORE BECAUSE OF ERROR LOADING RULESET!\n");
	// }
}

// // todo(fntlnz): not sure we want this in falco_engine
// void falco_engine::watch_rules(bool verbose, bool all_events)
// {
// 	hawk_watch_rules((hawk_watch_rules_cb)rules_cb, reinterpret_cast<hawk_engine *>(this));
// }

bool falco_engine::is_ready()
{
	return m_is_ready;
}

void falco_engine::enable_rule(const string &substring, bool enabled, const string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);
	bool match_exact = false;

	m_sinsp_rules->enable(substring, match_exact, enabled, ruleset_id);
	m_k8s_audit_rules->enable(substring, match_exact, enabled, ruleset_id);
}

void falco_engine::enable_rule(const string &substring, bool enabled)
{
	enable_rule(substring, enabled, m_default_ruleset);
}

void falco_engine::enable_rule_exact(const string &rule_name, bool enabled, const string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);
	bool match_exact = true;

	m_sinsp_rules->enable(rule_name, match_exact, enabled, ruleset_id);
	m_k8s_audit_rules->enable(rule_name, match_exact, enabled, ruleset_id);
}

void falco_engine::enable_rule_exact(const string &rule_name, bool enabled)
{
	enable_rule_exact(rule_name, enabled, m_default_ruleset);
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

	std::lock_guard<std::mutex> guard(m_ls_semaphore);
	lua_getglobal(m_ls, lua_on_event.c_str());
	if(lua_isfunction(m_ls, -1))
	{
		lua_pushnumber(m_ls, ev->get_check_id());

		if(lua_pcall(m_ls, 1, 3, 0) != 0)
		{
			const char *lerr = lua_tostring(m_ls, -1);
			string err = "Error invoking function output: " + string(lerr);
			throw falco_exception(err);
		}
		res->evt = ev;
		const char *p = lua_tostring(m_ls, -3);
		res->rule = p;
		res->source = "syscall";
		res->priority_num = (falco_common::priority_type)lua_tonumber(m_ls, -2);
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
	// todo(leodido, fntlnz) > pass the last ruleset id
	return process_sinsp_event(ev, m_default_ruleset_id);
}

unique_ptr<falco_engine::rule_result> falco_engine::process_k8s_audit_event(json_event *ev, uint16_t ruleset_id)
{
	if(should_drop_evt())
	{
		return unique_ptr<struct rule_result>();
	}

	// All k8s audit events have the single tag "1".
	if(!m_k8s_audit_rules->run((gen_event *)ev, 1, ruleset_id))
	{
		return unique_ptr<struct rule_result>();
	}

	unique_ptr<struct rule_result> res(new rule_result());

	std::lock_guard<std::mutex> guard(m_ls_semaphore);
	lua_getglobal(m_ls, lua_on_event.c_str());
	if(lua_isfunction(m_ls, -1))
	{
		lua_pushnumber(m_ls, ev->get_check_id());

		if(lua_pcall(m_ls, 1, 3, 0) != 0)
		{
			const char *lerr = lua_tostring(m_ls, -1);
			string err = "Error invoking function output: " + string(lerr);
			throw falco_exception(err);
		}
		res->evt = ev;
		const char *p = lua_tostring(m_ls, -3);
		res->rule = p;
		res->source = "k8s_audit";
		res->priority_num = (falco_common::priority_type)lua_tonumber(m_ls, -2);
		res->format = lua_tostring(m_ls, -1);
		lua_pop(m_ls, 3);
	}
	else
	{
		throw falco_exception("No function " + lua_on_event + " found in lua compiler module");
	}

	return res;
}

bool falco_engine::parse_k8s_audit_json(nlohmann::json &j, std::list<json_event> &evts, bool top)
{
	// Note that nlohmann::basic_json::value can throw  nlohmann::basic_json::type_error (302, 306)
	try
	{
		// If the object is an array, call parse_k8s_audit_json again for each item.
		if(j.is_array())
		{
			if(top)
			{
				for(auto &item : j)
				{
					// Note we only handle a single top level array, to
					// avoid excessive recursion.
					if(!parse_k8s_audit_json(item, evts, false))
					{
						return false;
					}
				}

				return true;
			}
			else
			{
				return false;
			}
		}

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
			const char *lerr = lua_tostring(m_ls, -1);
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
				    sinsp_filter *filter)
{
	m_sinsp_rules->add(rule, evttypes, syscalls, tags, filter);
}

void falco_engine::add_k8s_audit_filter(string &rule,
					set<string> &tags,
					json_event_filter *filter)
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

	double coin = (random() * (1.0 / RAND_MAX));
	return (coin >= (1.0 / (m_sampling_multiplier * m_sampling_ratio)));
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
