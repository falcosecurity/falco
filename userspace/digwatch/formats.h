#pragma once

#include "sinsp.h"
#include "lua_parser.h"

class sinsp_evt_formatter;

class digwatch_formats
{
 public:
	digwatch_formats(sinsp* inspector, lua_State *ls);

	// set_formatter(index, format_string)
	static int set_formatter(lua_State *ls);
	sinsp_evt_formatter* lookup_formatter(uint32_t index);

 private:
	lua_State* m_ls;
};
