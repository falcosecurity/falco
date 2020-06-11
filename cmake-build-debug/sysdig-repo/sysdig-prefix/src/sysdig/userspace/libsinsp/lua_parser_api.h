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

#pragma once

typedef struct lua_State lua_State;

class lua_parser_filtercheck
{
public:

	lua_parser_filtercheck() {};
	virtual ~lua_parser_filtercheck() {};

	boolop m_boolop;
	cmpop m_cmpop;

	virtual int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering) = 0;

	virtual void add_filter_value(const char* str, uint32_t len, uint32_t i = 0 ) = 0;

	virtual void set_check_id(int32_t id) = 0;
};

class lua_parser_filter
{
public:
	lua_parser_filter() {};
	virtual ~lua_parser_filter() {};

	virtual void push_expression(boolop op) = 0;
	virtual void pop_expression() = 0;
	virtual void add_check(lua_parser_filtercheck* chk) = 0;
};

class lua_filter_factory
{
public:

	lua_filter_factory() {};
	virtual ~lua_filter_factory() {};

	// Create a new filter
	virtual lua_parser_filter *new_filter() = 0;

	// Create a new filterchekc
	virtual lua_parser_filtercheck *new_filtercheck(const char *fldname) = 0;
};

class lua_parser_cbacks
{
public:
	// filter.rel_expr(field_name, cmpop, value, index)
	// field_name and cmpop are mandatory
	// value is mandatory unless cmpop=="exists"
	// index is an optional index (integer) that will be written
	// into events matching this expression (internal use).
	static int rel_expr(lua_State *ls);

	// filter.bool_op(op)
	static int bool_op(lua_State *ls);

	// filter.nest()
	static int nest(lua_State *ls);

	// filter.unnest()
	static int unnest(lua_State *ls);
};

