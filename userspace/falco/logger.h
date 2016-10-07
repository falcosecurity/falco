/*
Copyright (C) 2016 Draios inc.

This file is part of falco.

falco is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

falco is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with falco.  If not, see <http://www.gnu.org/licenses/>.
*/

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
