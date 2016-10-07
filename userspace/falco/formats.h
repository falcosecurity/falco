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
