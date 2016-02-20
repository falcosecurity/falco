#pragma once

#include "sinsp.h"
#include "lua_parser.h"

class digwatch_rules
{
 public:
	digwatch_rules(sinsp* inspector, string compiler_filename);
	~digwatch_rules();
	void load(string rules_filename);
	sinsp_filter* get_filter();

 private:
	lua_parser* m_lua_parser;
	lua_State* m_ls;
};
