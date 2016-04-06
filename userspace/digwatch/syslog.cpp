#include "syslog.h"
#include "chisel_api.h"
#include "filterchecks.h"

#include <syslog.h>


const static struct luaL_reg ll_digwatch [] =
{
	{"syslog", &digwatch_syslog::syslog},
	{NULL,NULL}
};


void digwatch_syslog::init(lua_State *ls)
{
	luaL_openlib(ls, "digwatch", ll_digwatch, 0);
}

int digwatch_syslog::syslog(lua_State *ls) {
	int priority = luaL_checknumber(ls, 1);

	if (priority > LOG_DEBUG) {
		return luaL_argerror(ls, 1, "digwatch.syslog: priority must be a number between 0 and 7");
	}

	const char *msg = luaL_checkstring(ls, 2);
	::syslog(priority, "%s", msg);

	return 0;
}

