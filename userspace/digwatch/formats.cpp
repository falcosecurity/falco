#include "formats.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

std::map<uint32_t, sinsp_evt_formatter*> g_format_map;
sinsp* g_inspector;

const static struct luaL_reg ll_digwatch [] =
{
	{"set_formatter", &digwatch_formats::set_formatter},
	{NULL,NULL}
};

digwatch_formats::digwatch_formats(sinsp* inspector, lua_State *ls)
{
	g_inspector = inspector;

	m_ls = ls;

	luaL_openlib(m_ls, "digwatch", ll_digwatch, 0);
}

int digwatch_formats::set_formatter (lua_State *ls) {
	uint32_t index = luaL_checkinteger(ls, 1);
	string format = luaL_checkstring(ls, 2);

	try
	{
		if(format == "" || format == "default")
		{
			g_format_map[index] = new sinsp_evt_formatter(g_inspector, DEFAULT_OUTPUT_STR);
		}
		else
		{
			g_format_map[index] = new sinsp_evt_formatter(g_inspector, format);
		}
	}
	catch(sinsp_exception& e)
	{
		string err = "invalid output format " + format;
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("set_formatter error");
	}

	return 0;
}

sinsp_evt_formatter* digwatch_formats::lookup_formatter(uint32_t index)
{
	return g_format_map[index];
}


