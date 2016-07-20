#pragma once

#include <list>

#include "sinsp.h"

#include "lua_parser.h"

class falco_engine;

class falco_rules
{
 public:
	falco_rules(sinsp* inspector, falco_engine *engine, lua_State *ls);
	~falco_rules();
	void load_rules(const string &rules_content, bool verbose, bool all_events);
	void describe_rule(string *rule);

	static void init(lua_State *ls);
	static int add_filter(lua_State *ls);

 private:
	void add_filter(string &rule, list<uint32_t> &evttypes);

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
