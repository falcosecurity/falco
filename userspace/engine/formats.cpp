/*
Copyright (C) 2020 The Falco Authors.

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

#include <json/json.h>

#include "formats.h"
#include "falco_engine.h"
#include "banned.h" // This raises a compilation error when certain functions are used

sinsp *falco_formats::s_inspector = NULL;
falco_engine *falco_formats::s_engine = NULL;
bool falco_formats::s_json_output = false;
bool falco_formats::s_json_include_output_property = true;
std::unique_ptr<sinsp_evt_formatter_cache> falco_formats::s_formatters = NULL;

const static struct luaL_Reg ll_falco[] =
	{
		{"formatter", &falco_formats::lua_formatter},
		{"free_formatter", &falco_formats::lua_free_formatter},
		{NULL, NULL}};

void falco_formats::init(sinsp *inspector,
			 falco_engine *engine,
			 lua_State *ls,
			 bool json_output,
			 bool json_include_output_property)
{
	s_inspector = inspector;
	s_engine = engine;
	s_json_output = json_output;
	s_json_include_output_property = json_include_output_property;

	// todo(leogr): we should have used std::make_unique, but we cannot since it's not C++14
	s_formatters = std::unique_ptr<sinsp_evt_formatter_cache>(new sinsp_evt_formatter_cache(s_inspector));

	luaL_openlib(ls, "formats", ll_falco, 0);
}

int falco_formats::lua_formatter(lua_State *ls)
{
	string source = luaL_checkstring(ls, -2);
	string format = luaL_checkstring(ls, -1);

	try
	{
		if(source == "syscall")
		{
			sinsp_evt_formatter *formatter;
			formatter = new sinsp_evt_formatter(s_inspector, format);
			lua_pushlightuserdata(ls, formatter);
		}
		else
		{
			json_event_formatter *formatter;
			formatter = new json_event_formatter(s_engine->json_factory(), format);
			lua_pushlightuserdata(ls, formatter);
		}
	}
	catch(sinsp_exception &e)
	{
		luaL_error(ls, "Invalid output format '%s': '%s'", format.c_str(), e.what());
	}
	catch(falco_exception &e)
	{
		luaL_error(ls, "Invalid output format '%s': '%s'", format.c_str(), e.what());
	}

	return 1;
}

int falco_formats::lua_free_formatter(lua_State *ls)
{
	if(!lua_islightuserdata(ls, -1) ||
	   !lua_isstring(ls, -2))

	{
		luaL_error(ls, "Invalid argument passed to free_formatter");
	}

	string source = luaL_checkstring(ls, -2);

	if(source == "syscall")
	{
		sinsp_evt_formatter *formatter = (sinsp_evt_formatter *)lua_topointer(ls, -1);
		delete(formatter);
	}
	else
	{
		json_event_formatter *formatter = (json_event_formatter *)lua_topointer(ls, -1);
		delete(formatter);
	}

	return 0;
}

string falco_formats::format_event(const gen_event *evt, const std::string &rule, const std::string &source,
				   const std::string &level, const std::string &format)
{

	string line;
	string json_line;
	string sformat = format;

	if(strcmp(source.c_str(), "syscall") == 0)
	{
		// This is "output"
		s_formatters->tostring((sinsp_evt *)evt, sformat, &line);

		if(s_json_output)
		{
			sinsp_evt::param_fmt cur_fmt = s_inspector->get_buffer_format();
			switch(cur_fmt)
			{
			case sinsp_evt::PF_NORMAL:
				s_inspector->set_buffer_format(sinsp_evt::PF_JSON);
				break;
			case sinsp_evt::PF_EOLS:
				s_inspector->set_buffer_format(sinsp_evt::PF_JSONEOLS);
				break;
			case sinsp_evt::PF_HEX:
				s_inspector->set_buffer_format(sinsp_evt::PF_JSONHEX);
				break;
			case sinsp_evt::PF_HEXASCII:
				s_inspector->set_buffer_format(sinsp_evt::PF_JSONHEXASCII);
				break;
			case sinsp_evt::PF_BASE64:
				s_inspector->set_buffer_format(sinsp_evt::PF_JSONBASE64);
				break;
			default:
				// do nothing
				break;
			}
			// This is output fields
			s_formatters->tostring((sinsp_evt *)evt, sformat, &json_line);

			// The formatted string might have a leading newline. If it does, remove it.
			if(json_line[0] == '\n')
			{
				json_line.erase(0, 1);
			}
			s_inspector->set_buffer_format(cur_fmt);
		}
	}
	else
	{
		json_event_formatter formatter(s_engine->json_factory(), sformat);

		line = formatter.tostring((json_event *)evt);

		if(s_json_output)
		{
			json_line = formatter.tojson((json_event *)evt);
		}
	}

	// For JSON output, the formatter returned a json-as-text
	// object containing all the fields in the original format
	// message as well as the event time in ns. Use this to build
	// a more detailed object containing the event time, rule,
	// severity, full output, and fields.
	if(s_json_output)
	{
		Json::Value event;
		Json::FastWriter writer;
		string full_line;

		// Convert the time-as-nanoseconds to a more json-friendly ISO8601.
		time_t evttime = evt->get_ts() / 1000000000;
		char time_sec[20]; // sizeof "YYYY-MM-DDTHH:MM:SS"
		char time_ns[12];  // sizeof ".sssssssssZ"
		string iso8601evttime;

		strftime(time_sec, sizeof(time_sec), "%FT%T", gmtime(&evttime));
		snprintf(time_ns, sizeof(time_ns), ".%09luZ", evt->get_ts() % 1000000000);
		iso8601evttime = time_sec;
		iso8601evttime += time_ns;
		event["time"] = iso8601evttime;
		event["rule"] = rule;
		event["priority"] = level;

		if(s_json_include_output_property)
		{
			// This is the filled-in output line.
			event["output"] = line;
		}

		full_line = writer.write(event);

		// Json::FastWriter may add a trailing newline. If it
		// does, remove it.
		if(full_line[full_line.length() - 1] == '\n')
		{
			full_line.resize(full_line.length() - 1);
		}

		// Cheat-graft the output from the formatter into this
		// string. Avoids an unnecessary json parse just to
		// merge the formatted fields at the object level.
		full_line.pop_back();
		full_line.append(", \"output_fields\": ");
		full_line.append(json_line);
		full_line.append("}");
		line = full_line;
	}

	return line.c_str();
}

map<string, string> falco_formats::resolve_tokens(const gen_event *evt, const std::string &source, const std::string &format)
{
	string sformat = format;
	map<string, string> values;
	if(source == "syscall")
	{
		s_formatters->resolve_tokens((sinsp_evt *)evt, sformat, values);
	}
	// k8s_audit
	else
	{
		json_event_formatter json_formatter(s_engine->json_factory(), sformat);
		values = json_formatter.tomap((json_event *)evt);
	}
	return values;
}
