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

#include "falco_outputs.h"

#include "config_falco.h"


#include "formats.h"
#include "logger.h"

using namespace std;

falco_outputs::falco_outputs(falco_engine *engine)
	: m_falco_engine(engine),
	  m_initialized(false),
	  m_buffered(true)
{

}

falco_outputs::~falco_outputs()
{
	// Note: The assert()s in this destructor were previously places where
	//       exceptions were thrown.  C++11 doesn't allow destructors to
	//       emit exceptions; if they're thrown, they'll trigger a call
	//       to 'terminate()'.  To maintain similar behavior, the exceptions
	//       were replace with calls to 'assert()'
	if(m_initialized)
	{
		lua_getglobal(m_ls, m_lua_output_cleanup.c_str());

		if(!lua_isfunction(m_ls, -1))
		{
			falco_logger::log(LOG_ERR, std::string("No function ") + m_lua_output_cleanup + " found. ");
			assert(nullptr == "Missing lua cleanup function in ~falco_outputs");
		}

		if(lua_pcall(m_ls, 0, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			falco_logger::log(LOG_ERR, std::string("lua_pcall failed, err: ") + lerr);
			assert(nullptr == "lua_pcall failed in ~falco_outputs");
		}
	}
}

void falco_outputs::init(bool json_output,
			 bool json_include_output_property,
			 uint32_t rate, uint32_t max_burst, bool buffered)
{
	// The engine must have been given an inspector by now.
	if(! m_inspector)
	{
		throw falco_exception("No inspector provided");
	}

	falco_common::init(m_lua_main_filename.c_str(), FALCO_SOURCE_LUA_DIR);

	// Note that falco_formats is added to both the lua state used
	// by the falco engine as well as the separate lua state used
	// by falco outputs.
	falco_formats::init(m_inspector, m_falco_engine, m_ls, json_output, json_include_output_property);

	falco_logger::init(m_ls);

	m_notifications_tb.init(rate, max_burst);

	m_buffered = buffered;

	m_initialized = true;
}

void falco_outputs::add_output(output_config oc)
{
	uint8_t nargs = 2;
	lua_getglobal(m_ls, m_lua_add_output.c_str());

	if(!lua_isfunction(m_ls, -1))
	{
		throw falco_exception("No function " + m_lua_add_output + " found. ");
	}
	lua_pushstring(m_ls, oc.name.c_str());
	lua_pushnumber(m_ls, (m_buffered ? 1 : 0));

	// If we have options, build up a lua table containing them
	if (oc.options.size())
	{
		nargs = 3;
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

void falco_outputs::handle_event(gen_event *ev, string &rule, string &source,
				 falco_common::priority_type priority, string &format)
{
	if(!m_notifications_tb.claim())
	{
		falco_logger::log(LOG_DEBUG, "Skipping rate-limited notification for rule " + rule + "\n");
		return;
	}

	lua_getglobal(m_ls, m_lua_output_event.c_str());

	if(lua_isfunction(m_ls, -1))
	{
		lua_pushlightuserdata(m_ls, ev);
		lua_pushstring(m_ls, rule.c_str());
		lua_pushstring(m_ls, source.c_str());
		lua_pushstring(m_ls, falco_common::priority_names[priority].c_str());
		lua_pushnumber(m_ls, priority);
		lua_pushstring(m_ls, format.c_str());

		if(lua_pcall(m_ls, 6, 0, 0) != 0)
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

void falco_outputs::reopen_outputs()
{
	lua_getglobal(m_ls, m_lua_output_reopen.c_str());

	if(!lua_isfunction(m_ls, -1))
	{
		throw falco_exception("No function " + m_lua_output_reopen + " found. ");
	}

	if(lua_pcall(m_ls, 0, 0, 0) != 0)
	{
		const char* lerr = lua_tostring(m_ls, -1);
		throw falco_exception(string(lerr));
	}
}
