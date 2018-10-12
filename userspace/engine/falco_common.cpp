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

#include <fstream>

#include "config_falco_engine.h"
#include "falco_common.h"

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

void falco_common::set_inspector(sinsp *inspector)
{
	m_inspector = inspector;
}

void falco_common::init(const char *lua_main_filename, const char *alternate_lua_dir)
{
	ifstream is;
	string lua_dir = FALCO_ENGINE_LUA_DIR;
	string lua_main_path = lua_dir + lua_main_filename;

	is.open(lua_main_path);
	if (!is.is_open())
	{
		lua_dir = alternate_lua_dir;
		lua_main_path = lua_dir + lua_main_filename;

		is.open(lua_main_path);
		if (!is.is_open())
		{
			throw falco_exception("Could not find Falco Lua entrypoint (tried " +
					      string(FALCO_ENGINE_LUA_DIR) + lua_main_filename + ", " +
					      string(alternate_lua_dir) + lua_main_filename + ")");
		}
	}

	// Initialize Lua interpreter
	add_lua_path(lua_dir);

	// Load the main program, which defines all the available functions.
	string scriptstr((istreambuf_iterator<char>(is)),
			 istreambuf_iterator<char>());

	if(luaL_loadstring(m_ls, scriptstr.c_str()) || lua_pcall(m_ls, 0, 0, 0))
	{
		throw falco_exception("Failed to load script " +
			lua_main_path + ": " + lua_tostring(m_ls, -1));
	}
}

void falco_common::add_lua_path(string &path)
{
	string cpath = string(path);
	path += "?.lua";
	cpath += "?.so";

	lua_getglobal(m_ls, "package");

	lua_getfield(m_ls, -1, "path");
	string cur_path = lua_tostring(m_ls, -1 );
	cur_path += ';';
	lua_pop(m_ls, 1);

	cur_path.append(path.c_str());

	lua_pushstring(m_ls, cur_path.c_str());
	lua_setfield(m_ls, -2, "path");

	lua_getfield(m_ls, -1, "cpath");
	string cur_cpath = lua_tostring(m_ls, -1 );
	cur_cpath += ';';
	lua_pop(m_ls, 1);

	cur_cpath.append(cpath.c_str());

	lua_pushstring(m_ls, cur_cpath.c_str());
	lua_setfield(m_ls, -2, "cpath");

	lua_pop(m_ls, 1);
}

