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

#pragma once

#include <set>

#include "sinsp.h"

#include "lua_parser.h"

class falco_engine;

class falco_rules
{
 public:
	falco_rules(sinsp* inspector, falco_engine *engine, lua_State *ls);
	~falco_rules();
	void load_rules(const string &rules_content, bool verbose, bool all_events,
			std::string &extra, bool replace_container_info);
	void describe_rule(string *rule);

	static void init(lua_State *ls);
	static int clear_filters(lua_State *ls);
	static int add_filter(lua_State *ls);
	static int enable_rule(lua_State *ls);

 private:
	void clear_filters();
	void add_filter(string &rule, std::set<uint32_t> &evttypes, std::set<string> &tags);
	void enable_rule(string &rule, bool enabled);

	lua_parser* m_lua_parser;
	sinsp* m_inspector;
	falco_engine *m_engine;
	lua_State* m_ls;

	string m_lua_load_rules = "load_rules";
	string m_lua_ignored_syscalls = "ignored_syscalls";
	string m_lua_ignored_events = "ignored_events";
	string m_lua_events = "events";
	string m_lua_describe_rule = "describe_rule";
};
