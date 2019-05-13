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

const static struct luaL_reg ll_falco_outputs [] =
{
	{"handle_http", &falco_outputs::handle_http},
	{NULL,NULL}
};

falco_outputs::falco_outputs(falco_engine *engine)
	: m_falco_engine(engine),
	  m_initialized(false),
	  m_buffered(true),
	  m_json_output(false),
	  m_time_format_iso_8601(false)
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
			 uint32_t rate, uint32_t max_burst, bool buffered,
			 bool time_format_iso_8601)
{
	// The engine must have been given an inspector by now.
	if(! m_inspector)
	{
		throw falco_exception("No inspector provided");
	}

	m_json_output = json_output;

	falco_common::init(m_lua_main_filename.c_str(), FALCO_SOURCE_LUA_DIR);

	// Note that falco_formats is added to both the lua state used
	// by the falco engine as well as the separate lua state used
	// by falco outputs.
	falco_formats::init(m_inspector, m_falco_engine, m_ls, json_output, json_include_output_property);

	falco_logger::init(m_ls);

	luaL_openlib(m_ls, "c_outputs", ll_falco_outputs, 0);

	m_notifications_tb.init(rate, max_burst);

	m_buffered = buffered;
	m_time_format_iso_8601 = time_format_iso_8601;

	m_initialized = true;
}

void falco_outputs::add_output(output_config oc)
{
	uint8_t nargs = 3;
	lua_getglobal(m_ls, m_lua_add_output.c_str());

	if(!lua_isfunction(m_ls, -1))
	{
		throw falco_exception("No function " + m_lua_add_output + " found. ");
	}
	lua_pushstring(m_ls, oc.name.c_str());
	lua_pushnumber(m_ls, (m_buffered ? 1 : 0));
	lua_pushnumber(m_ls, (m_time_format_iso_8601 ? 1 : 0));

	// If we have options, build up a lua table containing them
	if (oc.options.size())
	{
		nargs = 4;
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

void falco_outputs::handle_msg(uint64_t now,
			       falco_common::priority_type priority,
			       std::string &msg,
			       std::string &rule,
			       std::map<std::string,std::string> &output_fields)
{
	std::string full_msg;

	if(m_json_output)
	{
		nlohmann::json jmsg;

		// Convert the time-as-nanoseconds to a more json-friendly ISO8601.
		time_t evttime = now/1000000000;
		char time_sec[20]; // sizeof "YYYY-MM-DDTHH:MM:SS"
		char time_ns[12]; // sizeof ".sssssssssZ"
		string iso8601evttime;

		strftime(time_sec, sizeof(time_sec), "%FT%T", gmtime(&evttime));
		snprintf(time_ns, sizeof(time_ns), ".%09luZ", now % 1000000000);
		iso8601evttime = time_sec;
		iso8601evttime += time_ns;

		jmsg["output"] = msg;
		jmsg["priority"] = "Critical";
		jmsg["rule"] = rule;
		jmsg["time"] = iso8601evttime;
		jmsg["output_fields"] = output_fields;

		full_msg = jmsg.dump();
	}
	else
	{
		std::string timestr;
		bool first = true;

		sinsp_utils::ts_to_string(now, &timestr, false, true);
		full_msg = timestr + ": " + falco_common::priority_names[LOG_CRIT] + " " + msg + "(";
		for(auto &pair : output_fields)
		{
			if(first)
			{
				first = false;
			}
			else
			{
				full_msg += " ";
			}
			full_msg += pair.first + "=" + pair.second;
		}
		full_msg += ")";
	}

	lua_getglobal(m_ls, m_lua_output_msg.c_str());

	if(lua_isfunction(m_ls, -1))
	{
		lua_pushstring(m_ls, full_msg.c_str());
		lua_pushstring(m_ls, falco_common::priority_names[priority].c_str());
		lua_pushnumber(m_ls, priority);

		if(lua_pcall(m_ls, 3, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error invoking function output: " + string(lerr);
			throw falco_exception(err);
		}
	}
	else
	{
		throw falco_exception("No function " + m_lua_output_msg + " found in lua compiler module");
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

int falco_outputs::handle_http(lua_State *ls)
{
	CURL *curl = NULL;
	CURLcode res = CURLE_FAILED_INIT;
	struct curl_slist *slist1;
	slist1 = NULL;

	if (!lua_isstring(ls, -1) ||
	    !lua_isstring(ls, -2))
	{
		lua_pushstring(ls, "Invalid arguments passed to handle_http()");
		lua_error(ls);
	}

	string url = (char *) lua_tostring(ls, 1);
	string msg = (char *) lua_tostring(ls, 2);

	curl = curl_easy_init();
	if(curl)
	{
		slist1 = curl_slist_append(slist1, "Content-Type: application/json");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, msg.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, -1L);

		res = curl_easy_perform(curl);

		if(res != CURLE_OK) {
			falco_logger::log(LOG_ERR,"libcurl error: " + string(curl_easy_strerror(res)));
		}
		curl_easy_cleanup(curl);
		curl = NULL;
		curl_slist_free_all(slist1);
  		slist1 = NULL;
	}
	return 1;
}
