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

#include "falco_outputs.h"

#include "config_falco.h"


#include "formats.h"
#include "logger.h"

using namespace std;

falco_outputs::falco_outputs()
	: m_replace_container_info(false)
{

}

falco_outputs::~falco_outputs()
{

}

void falco_outputs::init(bool json_output)
{
	// The engine must have been given an inspector by now.
	if(! m_inspector)
	{
		throw falco_exception("No inspector provided");
	}

	falco_common::init(m_lua_main_filename.c_str(), FALCO_SOURCE_LUA_DIR);

	falco_formats::init(m_inspector, m_ls, json_output);

	falco_logger::init(m_ls);
}

void falco_outputs::set_extra(string &extra, bool replace_container_info)
{
	m_extra = extra;
	m_replace_container_info = replace_container_info;
}

void falco_outputs::add_output(output_config oc)
{
	uint8_t nargs = 1;
	lua_getglobal(m_ls, m_lua_add_output.c_str());

	if(!lua_isfunction(m_ls, -1))
	{
		throw falco_exception("No function " + m_lua_add_output + " found. ");
	}
	lua_pushstring(m_ls, oc.name.c_str());

	// If we have options, build up a lua table containing them
	if (oc.options.size())
	{
		nargs = 2;
		lua_createtable(m_ls, 0, oc.options.size());

		for (auto it = oc.options.cbegin(); it != oc.options.cend(); ++it)
		{
			lua_pushstring(m_ls, (*it).second.c_str());
			lua_setfield(m_ls, -2, (*it).first.c_str());
		}
	}

	if(lua_pcall(m_ls, nargs, 0, 0) != 0)
	{
		const char* lerr = lua_tostring(m_ls, -1);
		throw falco_exception(string(lerr));
	}

}

void falco_outputs::handle_event(sinsp_evt *ev, string &level, string &priority, string &format)
{
	lua_getglobal(m_ls, m_lua_output_event.c_str());

	// If the format string contains %container.info, replace it
	// with extra. Otherwise, add extra onto the end of the format
	// string.
	string format_w_extra = format;
	size_t pos;

	if((pos = format_w_extra.find("%container.info")) != string::npos)
	{
		// There may not be any extra, or we're not supposed
		// to replace it, in which case we use the generic
		// "%container.name (id=%container.id)"
		if(m_extra == "" || ! m_replace_container_info)
		{
			// 15 == strlen(%container.info)
			format_w_extra.replace(pos, 15, "%container.name (id=%container.id)");
		}
		else
		{
			format_w_extra.replace(pos, 15, m_extra);
		}
	}
	else
	{
		// Just add the extra to the end
		if (m_extra != "")
		{
			format_w_extra += " " + m_extra;
		}
	}

	if(lua_isfunction(m_ls, -1))
	{
		lua_pushlightuserdata(m_ls, ev);
		lua_pushstring(m_ls, level.c_str());
		lua_pushstring(m_ls, priority.c_str());
		lua_pushstring(m_ls, format_w_extra.c_str());

		if(lua_pcall(m_ls, 4, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error invoking function output: " + string(lerr);
			throw falco_exception(err);
		}
	}
	else
	{
		throw falco_exception("No function " + m_lua_output_event + " found in lua compiler module");
	}

}
