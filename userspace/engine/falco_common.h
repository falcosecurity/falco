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

	void init(const char *lua_main_filename, const char *source_dir);

	void set_inspector(sinsp *inspector);

protected:
	lua_State *m_ls;

	sinsp *m_inspector;

private:
	void add_lua_path(std::string &path);
};



