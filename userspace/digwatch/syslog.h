#pragma once

#include "sinsp.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

class digwatch_syslog
{
 public:
	static void init(lua_State *ls);

	// value = digwatch.syslog(level, message)
	static int syslog(lua_State *ls);
};
