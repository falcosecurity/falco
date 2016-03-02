#include "formats.h"


sinsp* digwatch_formats::s_inspector = NULL;

const static struct luaL_reg ll_digwatch [] =
{
	{"formatter", &digwatch_formats::formatter},
	{"format_event", &digwatch_formats::format_event},
	{NULL,NULL}
};

void digwatch_formats::init(sinsp* inspector, lua_State *ls)
{
	s_inspector = inspector;

	luaL_openlib(ls, "digwatch", ll_digwatch, 0);
}

int digwatch_formats::formatter(lua_State *ls)
{
	string format = luaL_checkstring(ls, 1);
	sinsp_evt_formatter* formatter;
	try
	{
		formatter = new sinsp_evt_formatter(s_inspector, format);
	}
	catch(sinsp_exception& e)
	{
		string err = "invalid output format " + format;
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("set_formatter error");
	}

	lua_pushlightuserdata(ls, formatter);

	return 1;
}

int digwatch_formats::format_event (lua_State *ls)
{
	string line;

	if (!lua_islightuserdata(ls, -1) || !lua_islightuserdata(ls, -2)) {
		string err = "invalid arguments passed to format_event() ";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("format_event error");
	}
	sinsp_evt* evt = (sinsp_evt*)lua_topointer(ls, 1);
	sinsp_evt_formatter* formatter = (sinsp_evt_formatter*)lua_topointer(ls, 2);

	formatter->tostring(evt, &line);

	lua_pushstring(ls, line.c_str());
	return 1;
}

