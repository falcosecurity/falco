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

#pragma once

#include <set>
#include <memory>

#include "sinsp.h"
#include "filter.h"

#include "json_evt.h"
#include "falco_common.h"

typedef struct lua_State lua_State;

class falco_engine;

class falco_rules
{
 public:
	falco_rules(falco_engine *engine,
		    lua_State *ls);
	~falco_rules();

	void add_filter_factory(const std::string &source,
				std::shared_ptr<gen_event_filter_factory> factory);

	std::shared_ptr<gen_event_filter_factory> get_filter_factory(const std::string &source);

	void load_rules(const string &rules_content, bool verbose, bool all_events,
			std::string &extra, bool replace_container_info,
			falco_common::priority_type min_priority,
			uint64_t &required_engine_version,
			std::map<std::string, std::list<std::string>> &required_plugin_versions);
	void describe_rule(string *rule);

	bool is_source_valid(const std::string &source);

	bool is_format_valid(const std::string &source, const std::string &format, std::string &errstr);

	bool is_defined_field(const std::string &source, const std::string &field);

	static void init(lua_State *ls);
	static int clear_filters(lua_State *ls);
	static int add_filter(lua_State *ls);
	static int enable_rule(lua_State *ls);
	static int engine_version(lua_State *ls);

	static int is_source_valid(lua_State *ls);

	// err = falco_rules.is_format_valid(source, format_string)
	static int is_format_valid(lua_State *ls);

	// err = falco_rules.is_defined_field(source, field)
	static int is_defined_field(lua_State *ls);

 private:
	void clear_filters();
	void add_filter(std::shared_ptr<gen_event_filter> filter, string &rule, string &source, std::set<string> &tags);
	void enable_rule(string &rule, bool enabled);

	falco_engine *m_engine;
	lua_State* m_ls;

	// Maps from event source to an object that can create rules
	// for that event source.
	std::map<std::string, std::shared_ptr<gen_event_filter_factory>> m_filter_factories;

	string m_lua_load_rules = "load_rules";
	string m_lua_describe_rule = "describe_rule";
};
