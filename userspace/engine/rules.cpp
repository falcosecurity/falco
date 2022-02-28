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

#include <sstream>

#include "rules.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include "falco_engine.h"
#include "banned.h" // This raises a compilation error when certain functions are used

const static struct luaL_Reg ll_falco_rules[] =
	{
		{"clear_filters", &falco_rules::clear_filters},
		{"add_filter", &falco_rules::add_filter},
		{"enable_rule", &falco_rules::enable_rule},
		{"engine_version", &falco_rules::engine_version},
		{"is_source_valid", &falco_rules::is_source_valid},
		{"is_format_valid", &falco_rules::is_format_valid},
		{"is_defined_field", &falco_rules::is_defined_field},
		{NULL, NULL}};

falco_rules::falco_rules(falco_engine *engine,
			 lua_State *ls)
	: m_engine(engine),
	  m_ls(ls)
{
}

void falco_rules::add_filter_factory(const std::string &source,
				     std::shared_ptr<gen_event_filter_factory> factory)
{
	m_filter_factories[source] = factory;
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

std::shared_ptr<gen_event_filter_factory> falco_rules::get_filter_factory(const std::string &source)
{
	auto it = m_filter_factories.find(source);
	if(it == m_filter_factories.end())
	{
		throw falco_exception(string("unknown event source: ") + source);
	}
	return it->second;
}

int falco_rules::add_filter(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -5) ||
	    ! lua_islightuserdata(ls, -4) ||
	    ! lua_isstring(ls, -3) ||
	    ! lua_isstring(ls, -2) ||
	    ! lua_istable(ls, -1))
	{
		lua_pushstring(ls, "Invalid arguments passed to add_filter()");
		lua_error(ls);
	}

	falco_rules *rules = (falco_rules *) lua_topointer(ls, -5);
	gen_event_filter *filter = (gen_event_filter*) lua_topointer(ls, -4);
	std::string rule = lua_tostring(ls, -3);
	std::string source = lua_tostring(ls, -2);

	set<string> tags;

	lua_pushnil(ls);  /* first key */
	while (lua_next(ls, -2) != 0) {
                // key is at index -2, value is at index
                // -1. We want the values.
		tags.insert(lua_tostring(ls, -1));

		// Remove value, keep key for next iteration
		lua_pop(ls, 1);
	}

	// todo(jasondellaluce,leogr,fededp): temp workaround, remove when fixed in libs
	size_t num_evttypes = 1; // assume plugin
	if(source == "syscall" || source == "k8s_audit")
	{
		num_evttypes = filter->evttypes().size();
	}

	try
	{
		std::shared_ptr<gen_event_filter> filter_ptr(filter);
		rules->add_filter(filter_ptr, rule, source, tags);
	}
	catch (exception &e)
	{
		std::string errstr = string("Could not add rule to falco engine: ") + e.what();
		lua_pushstring(ls, errstr.c_str());
		lua_error(ls);
	}

	lua_pushnumber(ls, num_evttypes);
	return 1;
}

void falco_rules::add_filter(std::shared_ptr<gen_event_filter> filter, string &rule, string &source, set<string> &tags)
{
	m_engine->add_filter(filter, rule, source, tags);
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

bool falco_rules::is_source_valid(const std::string &source)
{
	return m_engine->is_source_valid(source);
}

int falco_rules::is_source_valid(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -2) ||
	    ! lua_isstring(ls, -1))
	{
		lua_pushstring(ls, "Invalid arguments passed to is_source_valid");
		lua_error(ls);
	}

	falco_rules *rules = (falco_rules *) lua_topointer(ls, -2);
	string source = luaL_checkstring(ls, -1);

	bool ret = rules->is_source_valid(source);

	lua_pushboolean(ls, (ret ? 1 : 0));

	return 1;
}

int falco_rules::is_format_valid(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -3) ||
	    ! lua_isstring(ls, -2) ||
	    ! lua_isstring(ls, -1))
	{
		lua_pushstring(ls, "Invalid arguments passed to is_format_valid");
		lua_error(ls);
	}

	falco_rules *rules = (falco_rules *) lua_topointer(ls, -3);
	string source = luaL_checkstring(ls, -2);
	string format = luaL_checkstring(ls, -1);
	string errstr;

	bool ret = rules->is_format_valid(source, format, errstr);

	if (!ret)
	{
		lua_pushstring(ls, errstr.c_str());
	}
	else
	{
		lua_pushnil(ls);
	}

	return 1;
}

bool falco_rules::is_format_valid(const std::string &source, const std::string &format, std::string &errstr)
{
	bool ret = true;

	try
	{
		std::shared_ptr<gen_event_formatter> formatter;

		formatter = m_engine->create_formatter(source, format);
	}
	catch(exception &e)
	{
		std::ostringstream os;

		os << "Invalid output format '"
		   << format
		   << "': '"
		   << e.what()
		   << "'";

		errstr = os.str();
		ret = false;
	}

	return ret;
}

int falco_rules::is_defined_field(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -3) ||
	    ! lua_isstring(ls, -2) ||
	    ! lua_isstring(ls, -1))
	{
		lua_pushstring(ls, "Invalid arguments passed to is_defined_field");
		lua_error(ls);
	}

	falco_rules *rules = (falco_rules *) lua_topointer(ls, -3);
	string source = luaL_checkstring(ls, -2);
	string fldname = luaL_checkstring(ls, -1);

	bool ret = rules->is_defined_field(source, fldname);

	lua_pushboolean(ls, (ret ? 1 : 0));

	return 1;
}

bool falco_rules::is_defined_field(const std::string &source, const std::string &fldname)
{
	auto it = m_filter_factories.find(source);

	if(it == m_filter_factories.end())
	{
		return false;
	}

	auto *chk = it->second->new_filtercheck(fldname.c_str());

	if (chk == NULL)
	{
		return false;
	}

	delete(chk);

	return true;
}

static std::list<std::string> get_lua_table_values(lua_State *ls, int idx)
{
	std::list<std::string> ret;

	if (lua_isnil(ls, idx)) {
		return ret;
	}

	lua_pushnil(ls);  /* first key */
	while (lua_next(ls, idx-1) != 0) {
                // key is at index -2, value is at index
                // -1. We want the values.
		if (! lua_isstring(ls, -1)) {
			std::string err = "Non-string value in table of strings";
			throw falco_exception(err);
		}
		ret.push_back(string(lua_tostring(ls, -1)));

		// Remove value, keep key for next iteration
		lua_pop(ls, 1);
	}

	return ret;
}

static void get_lua_table_list_values(lua_State *ls,
				      int idx,
				      std::map<std::string, std::list<std::string>> &required_plugin_versions)
{
	if (lua_isnil(ls, idx)) {
		return;
	}

	lua_pushnil(ls);  /* first key */
	while (lua_next(ls, idx-1) != 0) {
                // key is at index -2, table of values is at index -1.
		if (! lua_isstring(ls, -2)) {
			std::string err = "Non-string key in table of strings";
			throw falco_exception(err);
		}

		std::string key = string(lua_tostring(ls, -2));
		std::list<std::string> vals = get_lua_table_values(ls, -1);

		if (required_plugin_versions.find(key) == required_plugin_versions.end())
		{
			required_plugin_versions[key] = vals;
		}
		else
		{
			required_plugin_versions[key].insert(required_plugin_versions[key].end(),
							     vals.begin(),
							     vals.end());
		}

		// Remove value, keep key for next iteration
		lua_pop(ls, 1);
	}
}


void falco_rules::load_rules(const string &rules_content,
			     bool verbose, bool all_events,
			     string &extra, bool replace_container_info,
			     falco_common::priority_type min_priority,
			     uint64_t &required_engine_version,
			     std::map<std::string, std::list<std::string>> &required_plugin_versions)
{
	lua_getglobal(m_ls, m_lua_load_rules.c_str());
	if(lua_isfunction(m_ls, -1))
	{
		lua_pushstring(m_ls, rules_content.c_str());
		lua_pushlightuserdata(m_ls, this);
		lua_pushboolean(m_ls, (verbose ? 1 : 0));
		lua_pushboolean(m_ls, (all_events ? 1 : 0));
		lua_pushstring(m_ls, extra.c_str());
		lua_pushboolean(m_ls, (replace_container_info ? 1 : 0));
		lua_pushnumber(m_ls, min_priority);
		if(lua_pcall(m_ls, 7, 5, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);

			string err = "Error loading rules: " + string(lerr);

			throw falco_exception(err);
		}

		// Returns:
		// Load result: bool
		// required engine version: will be nil when load result is false
		// required_plugin_versions: will be nil when load result is false
		// array of errors
		// array of warnings
		bool successful = lua_toboolean(m_ls, -5);
		required_engine_version = lua_tonumber(m_ls, -4);
		get_lua_table_list_values(m_ls, -3, required_plugin_versions);
		std::list<std::string> errors = get_lua_table_values(m_ls, -2);
		std::list<std::string> warnings = get_lua_table_values(m_ls, -1);

		// Concatenate errors/warnings
		std::ostringstream os;
		if (errors.size() > 0)
		{
			os << errors.size() << " errors:" << std::endl;
			for(auto err : errors)
			{
				os << err << std::endl;
			}
		}

		if (warnings.size() > 0)
		{
			os << warnings.size() << " warnings:" << std::endl;
			for(auto warn : warnings)
			{
				os << warn << std::endl;
			}
		}

		if(!successful)
		{
			throw falco_exception(os.str());
		}

		if (verbose && os.str() != "") {
			// We don't really have a logging callback
			// from the falco engine, but this would be a
			// good place to use it.
			fprintf(stderr, "When reading rules content: %s", os.str().c_str());
		}

		lua_pop(m_ls, 4);

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
}
