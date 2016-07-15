#include <json/json.h>

#include "formats.h"
#include "logger.h"
#include "falco_engine.h"


sinsp* falco_formats::s_inspector = NULL;
bool s_json_output = false;

const static struct luaL_reg ll_falco [] =
{
	{"formatter", &falco_formats::formatter},
	{"free_formatter", &falco_formats::free_formatter},
	{"format_event", &falco_formats::format_event},
	{NULL,NULL}
};

void falco_formats::init(sinsp* inspector, lua_State *ls, bool json_output)
{
	s_inspector = inspector;
	s_json_output = json_output;

	luaL_openlib(ls, "falco", ll_falco, 0);
}

int falco_formats::formatter(lua_State *ls)
{
	string format = luaL_checkstring(ls, 1);
	sinsp_evt_formatter* formatter;
	try
	{
		formatter = new sinsp_evt_formatter(s_inspector, format);
	}
	catch(sinsp_exception& e)
	{
		throw falco_exception("Invalid output format '" + format + "'.\n");
	}

	lua_pushlightuserdata(ls, formatter);

	return 1;
}

int falco_formats::free_formatter(lua_State *ls)
{
	if (!lua_islightuserdata(ls, -1))
	{
		throw falco_exception("Invalid argument passed to free_formatter");
	}

	sinsp_evt_formatter *formatter = (sinsp_evt_formatter *) lua_topointer(ls, 1);

	delete(formatter);

	return 1;
}

int falco_formats::format_event (lua_State *ls)
{
	string line;

	if (!lua_islightuserdata(ls, -1) ||
	    !lua_isstring(ls, -2) ||
	    !lua_isstring(ls, -3) ||
	    !lua_islightuserdata(ls, -4)) {
		throw falco_exception("Invalid arguments passed to format_event()\n");
	}
	sinsp_evt* evt = (sinsp_evt*)lua_topointer(ls, 1);
	const char *rule = (char *) lua_tostring(ls, 2);
	const char *level = (char *) lua_tostring(ls, 3);
	sinsp_evt_formatter* formatter = (sinsp_evt_formatter*)lua_topointer(ls, 4);

	formatter->tostring(evt, &line);

	// For JSON output, the formatter returned just the output
	// string containing the format text and values. Use this to
	// build a more detailed object containing the event time,
	// rule, severity, full output, and fields.
	if (s_json_output) {
		Json::Value event;
		Json::FastWriter writer;

		// Convert the time-as-nanoseconds to a more json-friendly ISO8601.
		time_t evttime = evt->get_ts()/1000000000;
		char time_sec[20]; // sizeof "YYYY-MM-DDTHH:MM:SS"
		char time_ns[12]; // sizeof ".sssssssssZ"
		string iso8601evttime;

		strftime(time_sec, sizeof(time_sec), "%FT%T", gmtime(&evttime));
		snprintf(time_ns, sizeof(time_ns), ".%09luZ", evt->get_ts() % 1000000000);
		iso8601evttime = time_sec;
		iso8601evttime += time_ns;
		event["time"] = iso8601evttime;
		event["rule"] = rule;
		event["priority"] = level;
		event["output"] = line;

		line = writer.write(event);

		// Json::FastWriter may add a trailing newline. If it
		// does, remove it.
		if (line[line.length()-1] == '\n')
		{
			line.resize(line.length()-1);
		}
	}

	lua_pushstring(ls, line.c_str());
	return 1;
}

