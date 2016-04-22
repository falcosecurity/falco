#pragma once

#include "sinsp.h"
#include <syslog.h>

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

	static void log(int priority, const string msg);

	static bool log_stderr;
	static bool log_syslog;
};
