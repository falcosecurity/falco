#pragma once

#include "sinsp.h"
#include "lua_parser.h"

class digwatch_rules
{
 public:
	digwatch_rules(sinsp* inspector, string lua_main_filename, string lua_dir);
	~digwatch_rules();
	void load_rules(string rules_filename);
	sinsp_filter* get_filter();

 private:
	void add_lua_path(string path);
	void load_compiler(string lua_main_filename);

	lua_parser* m_lua_parser;
	lua_State* m_ls;
	string m_lua_compiler_cb = "load_rules";
	string m_lua_;
};
