#pragma once

#include "sinsp.h"
#include <syslog.h>

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

class falco_logger
{
 public:
	static void init(lua_State *ls);

	// value = falco.syslog(level, message)
	static int syslog(lua_State *ls);

	static void log(int priority, const string msg);

	static bool log_stderr;
	static bool log_syslog;
};
