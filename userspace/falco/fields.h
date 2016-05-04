#pragma once

#include "sinsp.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

class falco_fields
{
 public:
	static void init(sinsp* inspector, lua_State *ls);

	// value = falco.field(evt, fieldname)
	static int field(lua_State *ls);

	static sinsp* s_inspector;
	static std::map<string, sinsp_filter_check*> s_fieldname_map;
};
