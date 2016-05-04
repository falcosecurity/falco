#include "formats.h"
#include "logger.h"


sinsp* falco_formats::s_inspector = NULL;

const static struct luaL_reg ll_falco [] =
{
	{"formatter", &falco_formats::formatter},
	{"format_event", &falco_formats::format_event},
	{NULL,NULL}
};

void falco_formats::init(sinsp* inspector, lua_State *ls)
{
	s_inspector = inspector;

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
		falco_logger::log(LOG_ERR, "Invalid output format '" + format + "'.\n");

		throw sinsp_exception("set_formatter error");
	}

	lua_pushlightuserdata(ls, formatter);

	return 1;
}

int falco_formats::format_event (lua_State *ls)
{
	string line;

	if (!lua_islightuserdata(ls, -1) || !lua_islightuserdata(ls, -2)) {
		falco_logger::log(LOG_ERR, "Invalid arguments passed to format_event()\n");
		throw sinsp_exception("format_event error");
	}
	sinsp_evt* evt = (sinsp_evt*)lua_topointer(ls, 1);
	sinsp_evt_formatter* formatter = (sinsp_evt_formatter*)lua_topointer(ls, 2);

	formatter->tostring(evt, &line);

	lua_pushstring(ls, line.c_str());
	return 1;
}

