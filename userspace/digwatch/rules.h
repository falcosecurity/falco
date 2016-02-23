#pragma once

#include "sinsp.h"
#include "lua_parser.h"

class sinsp_evt_formatter;

class digwatch_rules
{
 public:
	digwatch_rules(sinsp* inspector, string lua_main_filename, string lua_dir);
	~digwatch_rules();
	void load_rules(string rules_filename);
	sinsp_filter* get_filter();

	// set_formatter(index, format_string)
	static int set_formatter(lua_State *ls);
 private:
	void add_lua_path(string path);
	void load_compiler(string lua_main_filename);

	lua_parser* m_lua_parser;
	lua_State* m_ls;

	string m_lua_load_rule = "load_rule";
	string m_lua_on_done = "on_done";
	string m_lua_on_event = "on_event";
};
