#pragma once

#include "sinsp.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

class sinsp_evt_formatter;

class falco_formats
{
 public:
	static void init(sinsp* inspector, lua_State *ls, bool json_output);

	// formatter = falco.formatter(format_string)
	static int formatter(lua_State *ls);

	// falco.free_formatter(formatter)
	static int free_formatter(lua_State *ls);

	// formatted_string = falco.format_event(evt, formatter)
	static int format_event(lua_State *ls);

	static sinsp* s_inspector;

 private:
	lua_State* m_ls;
};
