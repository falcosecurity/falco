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

#include "rules.h"
#include "logger.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include "falco_engine.h"
const static struct luaL_reg ll_falco_rules [] =
{
	{"clear_filters", &falco_rules::clear_filters},
	{"add_filter", &falco_rules::add_filter},
	{"add_k8s_audit_filter", &falco_rules::add_k8s_audit_filter},
	{"enable_rule", &falco_rules::enable_rule},
	{"engine_version", &falco_rules::engine_version},
	{NULL,NULL}
};

falco_rules::falco_rules(sinsp* inspector,
			 falco_engine *engine,
			 lua_State *ls)
	: m_inspector(inspector),
	  m_engine(engine),
	  m_ls(ls)
{
	m_sinsp_lua_parser = new lua_parser(engine->sinsp_factory(), m_ls, "filter");
	m_json_lua_parser = new lua_parser(engine->json_factory(), m_ls, "k8s_audit_filter");
}

void falco_rules::init(lua_State *ls)
{
	luaL_openlib(ls, "falco_rules", ll_falco_rules, 0);
}

int falco_rules::clear_filters(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -1))
	{
		lua_pushstring(ls, "Invalid arguments passed to clear_filters()");
		lua_error(ls);
	}

	falco_rules *rules = (falco_rules *) lua_topointer(ls, -1);
	rules->clear_filters();

	return 0;
}

void falco_rules::clear_filters()
{
	m_engine->clear_filters();
}

int falco_rules::add_filter(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -5) ||
	    ! lua_isstring(ls, -4) ||
	    ! lua_istable(ls, -3) ||
	    ! lua_istable(ls, -2) ||
	    ! lua_istable(ls, -1))
	{
		lua_pushstring(ls, "Invalid arguments passed to add_filter()");
		lua_error(ls);
	}

	falco_rules *rules = (falco_rules *) lua_topointer(ls, -5);
	const char *rulec = lua_tostring(ls, -4);

	set<uint32_t> evttypes;

	lua_pushnil(ls);  /* first key */
	while (lua_next(ls, -4) != 0) {
                // key is at index -2, value is at index
                // -1. We want the keys.
		evttypes.insert(luaL_checknumber(ls, -2));

		// Remove value, keep key for next iteration
		lua_pop(ls, 1);
	}

	set<uint32_t> syscalls;

	lua_pushnil(ls);  /* first key */
	while (lua_next(ls, -3) != 0) {
                // key is at index -2, value is at index
                // -1. We want the keys.
		syscalls.insert(luaL_checknumber(ls, -2));

		// Remove value, keep key for next iteration
		lua_pop(ls, 1);
	}

	set<string> tags;

	lua_pushnil(ls);  /* first key */
	while (lua_next(ls, -2) != 0) {
                // key is at index -2, value is at index
                // -1. We want the values.
		tags.insert(lua_tostring(ls, -1));

		// Remove value, keep key for next iteration
		lua_pop(ls, 1);
	}

	std::string rule = rulec;
	rules->add_filter(rule, evttypes, syscalls, tags);

	return 0;
}

int falco_rules::add_k8s_audit_filter(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -3) ||
	    ! lua_isstring(ls, -2) ||
	    ! lua_istable(ls, -1))
	{
		lua_pushstring(ls, "Invalid arguments passed to add_k8s_audit_filter()");
		lua_error(ls);
	}

	falco_rules *rules = (falco_rules *) lua_topointer(ls, -3);
	const char *rulec = lua_tostring(ls, -2);

	set<string> tags;

	lua_pushnil(ls);  /* first key */
	while (lua_next(ls, -2) != 0) {
                // key is at index -2, value is at index
                // -1. We want the values.
		tags.insert(lua_tostring(ls, -1));

		// Remove value, keep key for next iteration
		lua_pop(ls, 1);
	}

	std::string rule = rulec;
	rules->add_k8s_audit_filter(rule, tags);

	return 0;
}

void falco_rules::add_filter(string &rule, set<uint32_t> &evttypes, set<uint32_t> &syscalls, set<string> &tags)
{
	// While the current rule was being parsed, a sinsp_filter
	// object was being populated by lua_parser. Grab that filter
	// and pass it to the engine.
	sinsp_filter *filter = (sinsp_filter *) m_sinsp_lua_parser->get_filter(true);

	m_engine->add_sinsp_filter(rule, evttypes, syscalls, tags, filter);
}

void falco_rules::add_k8s_audit_filter(string &rule, set<string> &tags)
{
	// While the current rule was being parsed, a sinsp_filter
	// object was being populated by lua_parser. Grab that filter
	// and pass it to the engine.
	json_event_filter *filter = (json_event_filter *) m_json_lua_parser->get_filter(true);

	m_engine->add_k8s_audit_filter(rule, tags, filter);
}

int falco_rules::enable_rule(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -3) ||
	    ! lua_isstring(ls, -2) ||
	    ! lua_isnumber(ls, -1))
	{
		lua_pushstring(ls, "Invalid arguments passed to enable_rule()");
		lua_error(ls);
	}

	falco_rules *rules = (falco_rules *) lua_topointer(ls, -3);
	const char *rulec = lua_tostring(ls, -2);
	std::string rule = rulec;
	bool enabled = (lua_tonumber(ls, -1) ? true : false);

	rules->enable_rule(rule, enabled);

	return 0;
}

void falco_rules::enable_rule(string &rule, bool enabled)
{
	m_engine->enable_rule(rule, enabled);
}

int falco_rules::engine_version(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -1))
	{
		lua_pushstring(ls, "Invalid arguments passed to engine_version()");
		lua_error(ls);
	}

	falco_rules *rules = (falco_rules *) lua_topointer(ls, -1);

	lua_pushnumber(ls, rules->m_engine->engine_version());

	return 1;
}

void falco_rules::load_rules(const string &rules_content,
			     bool verbose, bool all_events,
			     string &extra, bool replace_container_info,
			     falco_common::priority_type min_priority,
			     uint64_t &required_engine_version)
{
	lua_getglobal(m_ls, m_lua_load_rules.c_str());
	if(lua_isfunction(m_ls, -1))
	{
		// Create a table containing all events, so they can
		// be mapped to event ids.
		sinsp_evttables* einfo = m_inspector->get_event_info_tables();
		const struct ppm_event_info* etable = einfo->m_event_info;
		const struct ppm_syscall_desc* stable = einfo->m_syscall_info_table;

		map<string,string> events_by_name;
		for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
		{
			auto it = events_by_name.find(etable[j].name);

			if (it == events_by_name.end()) {
				events_by_name[etable[j].name] = to_string(j);
			} else {
				string cur = it->second;
				cur += " ";
				cur += to_string(j);
				events_by_name[etable[j].name] = cur;
			}
		}

		lua_newtable(m_ls);

		for( auto kv : events_by_name)
		{
			lua_pushstring(m_ls, kv.first.c_str());
			lua_pushstring(m_ls, kv.second.c_str());
			lua_settable(m_ls, -3);
		}

		lua_setglobal(m_ls, m_lua_events.c_str());

		map<string,string> syscalls_by_name;
		for(uint32_t j = 0; j < PPM_SC_MAX; j++)
		{
			auto it = syscalls_by_name.find(stable[j].name);

			if (it == syscalls_by_name.end())
			{
				syscalls_by_name[stable[j].name] = to_string(j);
			}
			else
			{
				string cur = it->second;
				cur += " ";
				cur += to_string(j);
				syscalls_by_name[stable[j].name] = cur;
			}
		}

		lua_newtable(m_ls);

		for( auto kv : syscalls_by_name)
		{
			lua_pushstring(m_ls, kv.first.c_str());
			lua_pushstring(m_ls, kv.second.c_str());
			lua_settable(m_ls, -3);
		}

		lua_setglobal(m_ls, m_lua_syscalls.c_str());

		// Create a table containing the syscalls/events that
		// are ignored by the kernel module. load_rules will
		// return an error if any rule references one of these
		// syscalls/events.

		lua_newtable(m_ls);

		for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
		{
			if(etable[j].flags & EF_DROP_FALCO)
			{
				lua_pushstring(m_ls, etable[j].name);
				lua_pushnumber(m_ls, 1);
				lua_settable(m_ls, -3);
			}
		}

		lua_setglobal(m_ls, m_lua_ignored_events.c_str());

		lua_newtable(m_ls);

		for(uint32_t j = 0; j < PPM_SC_MAX; j++)
		{
			if(stable[j].flags & EF_DROP_FALCO)
			{
				lua_pushstring(m_ls, stable[j].name);
				lua_pushnumber(m_ls, 1);
				lua_settable(m_ls, -3);
			}
		}

		lua_setglobal(m_ls, m_lua_ignored_syscalls.c_str());

		// Create a table containing all filtercheck names.
		lua_newtable(m_ls);

		vector<const filter_check_info*> fc_plugins;
		sinsp::get_filtercheck_fields_info(&fc_plugins);

		for(uint32_t j = 0; j < fc_plugins.size(); j++)
		{
			const filter_check_info* fci = fc_plugins[j];

			if(fci->m_flags & filter_check_info::FL_HIDDEN)
			{
				continue;
			}

			for(int32_t k = 0; k < fci->m_nfields; k++)
			{
				const filtercheck_field_info* fld = &fci->m_fields[k];

				if(fld->m_flags & EPF_TABLE_ONLY ||
				   fld->m_flags & EPF_PRINT_ONLY)
				{
					continue;
				}

				// Some filters can work with or without an argument
				std::set<string> flexible_filters = {
					"^proc.aname",
					"^proc.apid"
				};

				std::list<string> fields;
				std::string field_base = string("^") + fld->m_name;

				if(fld->m_flags & EPF_REQUIRES_ARGUMENT ||
				   flexible_filters.find(field_base) != flexible_filters.end())
				{
					fields.push_back(field_base + "[%[%.]");
				}

				if(!(fld->m_flags & EPF_REQUIRES_ARGUMENT) ||
				   flexible_filters.find(field_base) != flexible_filters.end())
				{
					fields.push_back(field_base + "$");
				}

				for(auto &field : fields)
				{
					lua_pushstring(m_ls, field.c_str());
					lua_pushnumber(m_ls, 1);
					lua_settable(m_ls, -3);
				}
			}
		}

		for(auto &chk_field : m_engine->json_factory().get_fields())
		{
			for(auto &field : chk_field.fields)
			{
				lua_pushstring(m_ls, field.name.c_str());
				lua_pushnumber(m_ls, 1);
				lua_settable(m_ls, -3);
			}
		}

		lua_setglobal(m_ls, m_lua_defined_filters.c_str());

		lua_pushlightuserdata(m_ls, m_sinsp_lua_parser);
		lua_pushlightuserdata(m_ls, m_json_lua_parser);
		lua_pushstring(m_ls, rules_content.c_str());
		lua_pushlightuserdata(m_ls, this);
		lua_pushboolean(m_ls, (verbose ? 1 : 0));
		lua_pushboolean(m_ls, (all_events ? 1 : 0));
		lua_pushstring(m_ls, extra.c_str());
		lua_pushboolean(m_ls, (replace_container_info ? 1 : 0));
		lua_pushnumber(m_ls, min_priority);
		if(lua_pcall(m_ls, 9, 1, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error loading rules: " + string(lerr);
			throw falco_exception(err);
		}

		required_engine_version = lua_tonumber(m_ls, -1);
		lua_pop(m_ls, 1);
	} else {
		throw falco_exception("No function " + m_lua_load_rules + " found in lua rule module");
	}
}

void falco_rules::describe_rule(std::string *rule)
{
	lua_getglobal(m_ls, m_lua_describe_rule.c_str());
	if(lua_isfunction(m_ls, -1))
	{
		if (rule == NULL)
		{
			lua_pushnil(m_ls);
		} else {
			lua_pushstring(m_ls, rule->c_str());
		}

		if(lua_pcall(m_ls, 1, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Could not describe " + (rule == NULL ? "all rules" : "rule " + *rule) + ": " + string(lerr);
			throw falco_exception(err);
		}
	} else {
		throw falco_exception("No function " + m_lua_describe_rule + " found in lua rule module");
	}
}


falco_rules::~falco_rules()
{
	delete m_sinsp_lua_parser;
	delete m_json_lua_parser;
}

