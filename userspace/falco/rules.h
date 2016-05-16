#pragma once

#include "sinsp.h"
#include "lua_parser.h"

class falco_rules
{
 public:
	falco_rules(sinsp* inspector, lua_State *ls, string lua_main_filename);
	~falco_rules();
	void load_rules(string rules_filename);
	void describe_rule(string *rule);
	sinsp_filter* get_filter();

 private:
	void load_compiler(string lua_main_filename);

	lua_parser* m_lua_parser;
	sinsp* m_inspector;
	lua_State* m_ls;

	string m_lua_load_rules = "load_rules";
	string m_lua_ignored_syscalls = "ignored_syscalls";
	string m_lua_ignored_events = "ignored_events";
	string m_lua_on_event = "on_event";
	string m_lua_describe_rule = "describe_rule";
};
