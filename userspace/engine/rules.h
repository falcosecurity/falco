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

#pragma once

#include <set>
#include <memory>

#include "sinsp.h"
#include "filter.h"

#include "lua_parser.h"

#include "json_evt.h"
#include "falco_common.h"

class falco_engine;

class falco_rules
{
 public:
	falco_rules(sinsp* inspector,
		    falco_engine *engine,
		    lua_State *ls);
	~falco_rules();
	void load_rules(const string &rules_content, bool verbose, bool all_events,
			std::string &extra, bool replace_container_info,
			falco_common::priority_type min_priority,
			uint64_t &required_engine_version);
	void describe_rule(string *rule);

	static void init(lua_State *ls);
	static int clear_filters(lua_State *ls);
	static int add_filter(lua_State *ls);
	static int add_k8s_audit_filter(lua_State *ls);
	static int enable_rule(lua_State *ls);
	static int engine_version(lua_State *ls);

 private:
	void clear_filters();
	void add_filter(string &rule, std::set<uint32_t> &evttypes, std::set<uint32_t> &syscalls, std::set<string> &tags);
	void add_k8s_audit_filter(string &rule, std::set<string> &tags);
	void enable_rule(string &rule, bool enabled);

	lua_parser* m_sinsp_lua_parser;
	lua_parser* m_json_lua_parser;
	sinsp* m_inspector;
	falco_engine *m_engine;
	lua_State* m_ls;

	string m_lua_load_rules = "load_rules";
	string m_lua_ignored_syscalls = "ignored_syscalls";
	string m_lua_ignored_events = "ignored_events";
	string m_lua_defined_filters = "defined_filters";
	string m_lua_events = "events";
	string m_lua_syscalls = "syscalls";
	string m_lua_describe_rule = "describe_rule";
};
