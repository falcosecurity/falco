/*
Copyright (C) 2016-2018 Draios Inc dba Sysdig.

This file is part of falco.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include "sinsp.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include "json_evt.h"
#include "falco_engine.h"

class sinsp_evt_formatter;

class falco_formats
{
 public:
	static void init(sinsp* inspector,
			 falco_engine *engine,
			 lua_State *ls,
			 bool json_output,
			 bool json_include_output_property);

	// formatter = falco.formatter(format_string)
	static int formatter(lua_State *ls);

	// falco.free_formatter(formatter)
	static int free_formatter(lua_State *ls);

	// falco.free_formatters()
	static int free_formatters(lua_State *ls);

	// formatted_string = falco.format_event(evt, formatter)
	static int format_event(lua_State *ls);

	static sinsp* s_inspector;
	static falco_engine *s_engine;
	static sinsp_evt_formatter_cache *s_formatters;
	static bool s_json_output;
	static bool s_json_include_output_property;
};
