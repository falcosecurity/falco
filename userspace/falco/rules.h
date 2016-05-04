#pragma once

#include "sinsp.h"
#include "lua_parser.h"

class falco_rules
{
 public:
	falco_rules(sinsp* inspector, lua_State *ls, string lua_main_filename);
	~falco_rules();
	void load_rules(string rules_filename);
	sinsp_filter* get_filter();

 private:
	void load_compiler(string lua_main_filename);

	lua_parser* m_lua_parser;
	lua_State* m_ls;

	string m_lua_load_rule = "load_rule";
	string m_lua_on_done = "on_done";
	string m_lua_on_event = "on_event";
};
