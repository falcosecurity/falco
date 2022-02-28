/*
Copyright (C) 2022 The Falco Authors.

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

#include <sinsp.h>
#include "lua_filter_helper.h"
#include "filter_macro_resolver.h"
#include "filter_list_resolver.h"
#include "rules.h"

using namespace std;
using namespace libsinsp::filter;

// The code below implements the Lua wrapper.
// todo(jasondellaluce): remove this once Lua is removed from Falco
extern "C" {
	#include "lua.h"
	#include "lualib.h"
	#include "lauxlib.h"
}

const static struct luaL_Reg ll_filter_helper[] =
{
	{"compile_filter", &lua_filter_helper::compile_filter},
	{"parse_filter", &lua_filter_helper::parse_filter},
	{"expand_list", &lua_filter_helper::expand_list},
	{"expand_macro", &lua_filter_helper::expand_macro},
	{"find_unknown_macro", &lua_filter_helper::find_unknown_macro},
	{"clone_ast", &lua_filter_helper::clone_ast},
	{"delete_ast", &lua_filter_helper::delete_ast},
	{NULL, NULL}
};

void lua_filter_helper::init(lua_State *ls)
{
	luaL_openlib(ls, "filter_helper", ll_filter_helper, 0);
}

int lua_filter_helper::parse_filter(lua_State *ls)
{
	if (! lua_isstring(ls, -1))
	{
		lua_pushstring(ls, "invalid argument passed to parse_filter()");
		lua_error(ls);
	}

	string filter_str = lua_tostring(ls, -1);

	parser p(filter_str);
	p.set_max_depth(1000);
	try
	{
		auto filter = p.parse();
		lua_pushboolean(ls, true);
		lua_pushlightuserdata(ls, filter);
	}
	catch (const sinsp_exception& e)
	{
		string err = to_string(p.get_pos().col) + ": " + e.what();
		lua_pushboolean(ls, false);
		lua_pushstring(ls, err.c_str());
	}
	return 2;
}

int lua_filter_helper::compile_filter(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -4) ||
		! lua_islightuserdata(ls, -3) ||
		! lua_isstring(ls, -2) ||
		! lua_isnumber(ls, -1))
	{
		lua_pushstring(ls, "invalid argument passed to compile_filter()");
		lua_error(ls);
	}

	falco_rules *rules = (falco_rules *) lua_topointer(ls, -4);
	ast::expr* ast = (ast::expr*) lua_topointer(ls, -3);
	std::string source = lua_tostring(ls, -2);
	int32_t check_id = (int32_t) luaL_checkinteger(ls, -1);

	try
	{
		sinsp_filter_compiler compiler(rules->get_filter_factory(source), ast);
		compiler.set_check_id(check_id);
		gen_event_filter* filter = compiler.compile();
		lua_pushboolean(ls, true);
		lua_pushlightuserdata(ls, filter);
	}
	catch (const sinsp_exception& e)
	{
		lua_pushboolean(ls, false);
		lua_pushstring(ls, e.what());
	}
	catch (const falco_exception& e)
	{
		lua_pushboolean(ls, false);
		lua_pushstring(ls, e.what());
	}
	return 2;
}

int lua_filter_helper::expand_list(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -3) ||	// ast
		! lua_isstring(ls, -2) ||		   // name
		! lua_istable(ls, -1))			  // values
	{
		lua_pushstring(ls, "invalid arguments passed to expand_list()");
		lua_error(ls);
	}

	ast::expr* ast = (ast::expr*) lua_topointer(ls, -3);
	std::string name = lua_tostring(ls, -2);
	vector<string> values;
	// first key
	lua_pushnil(ls);
	while (lua_next(ls, -2) != 0) {
		// key is at index -2, value is at index
		// -1. We want the values.
		values.push_back(lua_tostring(ls, -1));
		// Remove value, keep key for next iteration
		lua_pop(ls, 1);
	}
	
	filter_list_resolver resolver;
	resolver.define_list(name, values);
	resolver.process(ast);
	lua_pushboolean(ls, !resolver.get_resolved_lists().empty());
	lua_pushlightuserdata(ls, ast);
	return 2;
}

int lua_filter_helper::expand_macro(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -3) ||	// ast
		! lua_isstring(ls, -2) ||		   // name
		! lua_islightuserdata(ls, -1))	  // macro
	{
		lua_pushstring(ls, "invalid arguments passed to expand_macro()");
		lua_error(ls);
	}

	ast::expr* ast = (ast::expr*) lua_topointer(ls, -3);
	std::string name = lua_tostring(ls, -2);
	ast::expr* macro = (ast::expr*) lua_topointer(ls, -1);

	filter_macro_resolver resolver;
	resolver.define_macro(name, macro);
	resolver.process(ast);
	lua_pushboolean(ls, !resolver.get_resolved_macros().empty());
	lua_pushlightuserdata(ls, ast);
	return 2;
}

int lua_filter_helper::find_unknown_macro(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -1))	// ast
	{
		lua_pushstring(ls, "invalid arguments passed to find_unknown_macro()");
		lua_error(ls);
	}

	ast::expr* ast = (ast::expr*) lua_topointer(ls, -1);

	filter_macro_resolver resolver;
	resolver.process(ast);
	if (!resolver.get_unknown_macros().empty())
	{
		lua_pushboolean(ls, true);
		lua_pushstring(ls, resolver.get_unknown_macros().begin()->c_str());
	}
	else
	{
		lua_pushboolean(ls, false);
		lua_pushstring(ls, "");
	}
	return 2;
}

int lua_filter_helper::clone_ast(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -1))   // ast
	{
		lua_pushstring(ls, "Invalid arguments passed to clone_ast()");
		lua_error(ls);
	}

	ast::expr* ast = (ast::expr*) lua_topointer(ls, -1);
	ast::expr* cloned_ast = ast::clone(ast);
	lua_pushlightuserdata(ls, cloned_ast);
	return 1;
}

int lua_filter_helper::delete_ast(lua_State *ls)
{
	if (! lua_islightuserdata(ls, -1))  // ptr
	{
		lua_pushstring(ls, "Invalid arguments passed to delete_ast()");
		lua_error(ls);
	}

	delete (ast::expr*) lua_topointer(ls, -1);
	return 0;
}