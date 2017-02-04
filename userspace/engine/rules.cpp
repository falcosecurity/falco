/*
Copyright (C) 2016 Draios inc.

This file is part of falco.

falco is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

falco is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with falco.  If not, see <http://www.gnu.org/licenses/>.
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
	{"enable_rule", &falco_rules::enable_rule},
	{NULL,NULL}
};

falco_rules::falco_rules(sinsp* inspector, falco_engine *engine, lua_State *ls)
	: m_inspector(inspector), m_engine(engine), m_ls(ls)
{
	m_lua_parser = new lua_parser(inspector, m_ls);
}

void falco_rules::init(lua_State *ls)
{
	luaL_openlib(ls, "falco_rules", ll_falco_rules, 0);
}

int falco_rules::clear_filters(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -1))
	{
		throw falco_exception("Invalid arguments passed to clear_filters()\n");
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
	if (! lua_islightuserdata(ls, -4) ||
	    ! lua_isstring(ls, -3) ||
	    ! lua_istable(ls, -2) ||
	    ! lua_istable(ls, -1))
	{
		throw falco_exception("Invalid arguments passed to add_filter()\n");
	}

	falco_rules *rules = (falco_rules *) lua_topointer(ls, -4);
	const char *rulec = lua_tostring(ls, -3);

	set<uint32_t> evttypes;

	lua_pushnil(ls);  /* first key */
	while (lua_next(ls, -3) != 0) {
                // key is at index -2, value is at index
                // -1. We want the keys.
		evttypes.insert(luaL_checknumber(ls, -2));

		// Remove value, keep key for next iteration
		lua_pop(ls, 1);
	}

	set<string> tags;

	lua_pushnil(ls);  /* first key */
	while (lua_next(ls, -2) != 0) {
                // key is at index -2, value is at index
                // -1. We want the keys.
		tags.insert(lua_tostring(ls, -1));

		// Remove value, keep key for next iteration
		lua_pop(ls, 1);
	}

	std::string rule = rulec;
	rules->add_filter(rule, evttypes, tags);

	return 0;
}

void falco_rules::add_filter(string &rule, set<uint32_t> &evttypes, set<string> &tags)
{
	// While the current rule was being parsed, a sinsp_filter
	// object was being populated by lua_parser. Grab that filter
	// and pass it to the engine.
	sinsp_filter *filter = m_lua_parser->get_filter(true);

	m_engine->add_evttype_filter(rule, evttypes, tags, filter);
}

int falco_rules::enable_rule(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -3) ||
	    ! lua_isstring(ls, -2) ||
	    ! lua_isnumber(ls, -1))
	{
		throw falco_exception("Invalid arguments passed to enable_rule()\n");
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

void falco_rules::load_rules(const string &rules_content,
			     bool verbose, bool all_events,
			     string &extra, bool replace_container_info)
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

		lua_pushstring(m_ls, rules_content.c_str());
		lua_pushlightuserdata(m_ls, this);
		lua_pushboolean(m_ls, (verbose ? 1 : 0));
		lua_pushboolean(m_ls, (all_events ? 1 : 0));
		lua_pushstring(m_ls, extra.c_str());
		lua_pushboolean(m_ls, (replace_container_info ? 1 : 0));
		if(lua_pcall(m_ls, 6, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error loading rules:" + string(lerr);
			throw falco_exception(err);
		}
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
	delete m_lua_parser;
}

