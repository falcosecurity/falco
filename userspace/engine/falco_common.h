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

#include <string>
#include <exception>

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include <sinsp.h>

//
// Most falco_* classes can throw exceptions. Unless directly related
// to low-level failures like inability to open file, etc, they will
// be of this type.
//

struct falco_exception : std::exception
{
	falco_exception()
	{
	}

	virtual ~falco_exception() throw()
	{
	}

	falco_exception(std::string error_str)
	{
		m_error_str = error_str;
	}

	char const* what() const throw()
	{
		return m_error_str.c_str();
	}

	std::string m_error_str;
};

//
// This is the base class of falco_engine/falco_output. It is
// responsible for managing a lua state and associated inspector and
// loading a single "main" lua file into that state.
//

class falco_common
{
public:
	falco_common();
	virtual ~falco_common();

	void init(const char *lua_main_filename, const char *alternate_lua_dir);

	void set_inspector(sinsp *inspector);

        // Priority levels, as a vector of strings
	static std::vector<std::string> priority_names;

	// Same as numbers/indices into the above vector
	enum priority_type
	{
		PRIORITY_EMERGENCY = 0,
		PRIORITY_ALERT = 1,
		PRIORITY_CRITICAL = 2,
		PRIORITY_ERROR = 3,
		PRIORITY_WARNING = 4,
		PRIORITY_NOTICE = 5,
		PRIORITY_INFORMATIONAL = 6,
		PRIORITY_DEBUG = 7
	};

protected:
	lua_State *m_ls;

	sinsp *m_inspector;

private:
	void add_lua_path(std::string &path);
};



