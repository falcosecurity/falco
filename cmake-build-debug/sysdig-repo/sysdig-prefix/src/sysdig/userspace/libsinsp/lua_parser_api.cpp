/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

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
#include "sinsp.h"
#include "sinsp_int.h"

#include "filterchecks.h"
#include "lua_parser_api.h"
#include "lua_parser.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

extern sinsp_filter_check_list g_filterlist;

// It would be nice to expose this up to Lua so that comparison operator
// parsing/encoding can be done there.
static cmpop string_to_cmpop(const char* str)
{
	if(strcmp(str, "=") == 0)
	{
		return CO_EQ;
	}
	else if(strcmp(str, "!=") == 0)
	{
		return CO_NE;
	}
	else if(strcmp(str, "<=") == 0)
	{
		return CO_LE;
	}
	else if(strcmp(str, "<") == 0)
	{
		return CO_LT;
	}
	else if(strcmp(str, ">=") == 0)
	{
		return CO_GE;
	}
	else if(strcmp(str, ">") == 0)
	{
		return CO_GT;
	}
	else if(strcmp(str, "contains") == 0)
	{
		return CO_CONTAINS;
	}
	else if(strcmp(str, "icontains") == 0)
	{
		return CO_ICONTAINS;
	}
	else if(strcmp(str, "startswith") == 0)
	{
		return CO_STARTSWITH;
	}
	else if(strcmp(str, "endswith") == 0)
	{
		return CO_ENDSWITH;
	}
	else if(strcmp(str, "in") == 0)
	{
		return CO_IN;
	}
	else if(strcmp(str, "intersects") == 0)
	{
		return CO_INTERSECTS;
	}
	else if(strcmp(str, "pmatch") == 0)
	{
		return CO_PMATCH;
	}
	else if(strcmp(str, "exists") == 0)
	{
		return CO_EXISTS;
	}
	else if(strcmp(str, "glob") == 0)
	{
		return CO_GLOB;
	}
	else
	{
		throw sinsp_exception("filter error: invalid comparison operator: " + string(str));
	}
}

boolop string_to_boolop(const char* str)
{
	if(strcmp(str, "or") == 0)
	{
		return BO_OR;
	}
	else if(strcmp(str, "and") == 0)
	{
		return BO_AND;
	}
	else if(strcmp(str, "not") == 0)
	{
		return BO_NOT;
	}
	else
	{
		throw sinsp_exception("filter error: invalid boolean operator: " + string(str));
	}
}

int lua_parser_cbacks::nest(lua_State *ls)
{
	lua_parser* parser = (lua_parser*)lua_topointer(ls, -1);

	try {

		if (parser->m_have_rel_expr && parser->m_last_boolop == BO_NONE)
		{
			string err = "filter.nest() called without a preceding call to filter.bool_op()";
			throw sinsp_exception(err);
		}

		gen_event_filter* filter = parser->m_filter;

		filter->push_expression(parser->m_last_boolop);
		parser->m_nest_level++;

		parser->m_last_boolop = BO_NONE;
		parser->m_have_rel_expr = false;
	}
	catch (const std::exception& e)
	{
		lua_pushstring(ls, e.what());
		lua_error(ls);
	}

	return 0;
}

int lua_parser_cbacks::unnest(lua_State *ls)
{
	lua_parser* parser = (lua_parser*)lua_topointer(ls, -1);

	try {

		if (parser->m_nest_level < 1)
		{
			string err = "filter.unnest() called without being nested";
			throw sinsp_exception(err);
		}

		gen_event_filter* filter = parser->m_filter;

		filter->pop_expression();
		parser->m_nest_level--;
	}
	catch (const std::exception& e)
	{
		lua_pushstring(ls, e.what());
		lua_error(ls);
	}

	return 0;
}

int lua_parser_cbacks::bool_op(lua_State *ls)
{
	lua_parser* parser = (lua_parser*)lua_topointer(ls, -2);

	try {

		const char* opstr = luaL_checkstring(ls, -1);
		boolop op = string_to_boolop(opstr);

		if (!parser->m_have_rel_expr)
		{
			if (op == BO_NOT) {
				op = (boolop)((uint32_t)parser->m_last_boolop | op);
			}
			else
			{
				string err = "filter.bool_op() called without having called rel_expr() ";
				throw sinsp_exception(err);
			}
		}

		if (parser->m_last_boolop != BO_NONE)
		{
			if (op == BO_NOT) {
				op = (boolop)((uint32_t)parser->m_last_boolop | op);
			}
			else
			{
				string err = "filter.bool_op() called twice in a row";
				throw sinsp_exception(err);
			}
		}
		parser->m_last_boolop = op;

	}
	catch (const std::exception& e)
	{
		lua_pushstring(ls, e.what());
		lua_error(ls);
	}
	return 0;

}

int lua_parser_cbacks::rel_expr(lua_State *ls)
{
	lua_parser* parser = (lua_parser*)lua_topointer(ls, 1);

	try {

		if (parser->m_have_rel_expr && parser->m_last_boolop == BO_NONE)
		{
			string err = "filter.rel_expr() called twice in a row";
			throw sinsp_exception(err);
		}

		parser->m_have_rel_expr = true;
		gen_event_filter* filter = parser->m_filter;

		const char* fld = luaL_checkstring(ls, 2);
		gen_event_filter_check *chk = parser->m_factory.new_filtercheck(fld);
		if(chk == NULL)
		{
			string err = "filter_check called with nonexistent field " + string(fld);
			throw sinsp_exception("parser API error");
		}

		int i;
		int rule_index = 0;

		chk->m_boolop = parser->m_last_boolop;
		parser->m_last_boolop = BO_NONE;

		chk->parse_field_name(fld, true, true);

		const char* cmpop = luaL_checkstring(ls, 3);
		chk->m_cmpop = string_to_cmpop(cmpop);

		// "exists" is the only unary comparison op
		if(strcmp(cmpop, "exists"))
		{
			if (strcmp(cmpop, "in") == 0 ||
			    strcmp(cmpop, "intersects") == 0 ||
			    strcmp(cmpop, "pmatch") == 0)
			{
				if (!lua_istable(ls, 4))
				{
					string err = "Got non-table as in-expression operand\n";
					throw sinsp_exception("parser API error");
				}
				int n = luaL_getn(ls, 4);  /* get size of table */
				for (i=1; i<=n; i++)
				{
					lua_rawgeti(ls, 4, i);
					const char* value = luaL_checkstring(ls, 6);
					chk->add_filter_value(value, strlen(value), i - 1);
					lua_pop(ls, 1);
				}
			}
			else
			{
				const char* value = luaL_checkstring(ls, 4);
				chk->add_filter_value(value, strlen(value));
			}

			if (lua_isnumber(ls, 5))
			{
				rule_index = (int) luaL_checkinteger(ls, 5);
			}
		}
		else
		{
			if (lua_isnumber(ls, 4))
			{
				rule_index = (int) luaL_checkinteger(ls, 4);
			}
		}

		if (rule_index)
		{
			chk->set_check_id(rule_index);
		}

		filter->add_check(chk);

	}
	catch (const std::exception& e)
	{
		lua_pushstring(ls, e.what());
		lua_error(ls);
	}

	return 0;
}

