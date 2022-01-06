/*
Copyright (C) 2019 The Falco Authors.

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

#include <fstream>

#include "config_falco_engine.h"
#include "falco_common.h"
#include "banned.h" // This raises a compilation error when certain functions are used
#include "falco_engine_lua_files.hh"

std::vector<std::string> falco_common::priority_names = {
	"Emergency",
	"Alert",
	"Critical",
	"Error",
	"Warning",
	"Notice",
	"Informational",
	"Debug"};

falco_common::falco_common()
{
	m_ls = lua_open();
	if(!m_ls)
	{
		throw falco_exception("Cannot open lua");
	}
	luaL_openlibs(m_ls);
}

falco_common::~falco_common()
{
	if(m_ls)
	{
		lua_close(m_ls);
	}
}

void falco_common::init()
{
	// Strings in the list lua_module_strings need to be loaded as
	// lua modules, which also involves adding them to the
	// package.module table.
	for(const auto &pair : lua_module_strings)
	{
		lua_getglobal(m_ls, "package");
		lua_getfield(m_ls, -1, "preload");

		if(luaL_loadstring(m_ls, pair.first))
		{
			throw falco_exception("Failed to load embedded lua code " +
					      string(pair.second) + ": " + lua_tostring(m_ls, -1));
		}

		lua_setfield(m_ls, -2, pair.second);
	}

	// Strings in the list lua_code_strings need to be loaded and
	// evaluated so any public functions can be directly called.
	for(const auto &str : lua_code_strings)
	{
		if(luaL_loadstring(m_ls, str) || lua_pcall(m_ls, 0, 0, 0))
		{
			throw falco_exception("Failed to load + evaluate embedded lua code " +
					      string(str) + ": " + lua_tostring(m_ls, -1));
		}
	}
}
