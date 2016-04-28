#include <ctime>
#include "logger.h"
#include "chisel_api.h"
#include "filterchecks.h"



const static struct luaL_reg ll_digwatch [] =
{
	{"syslog", &digwatch_logger::syslog},
	{NULL,NULL}
};


void digwatch_logger::init(lua_State *ls)
{
	luaL_openlib(ls, "digwatch", ll_digwatch, 0);
}

int digwatch_logger::syslog(lua_State *ls) {
	int priority = luaL_checknumber(ls, 1);

	if (priority > LOG_DEBUG) {
		return luaL_argerror(ls, 1, "digwatch.syslog: priority must be a number between 0 and 7");
	}

	const char *msg = luaL_checkstring(ls, 2);
	::syslog(priority, "%s", msg);

	return 0;
}

bool digwatch_logger::log_stderr;
bool digwatch_logger::log_syslog;

void digwatch_logger::log(int priority, const string msg) {
	if (digwatch_logger::log_syslog) {
		::syslog(priority, "%s", msg.c_str());
	}

	if (digwatch_logger::log_stderr) {
		std::time_t result = std::time(nullptr);
		string tstr = std::asctime(std::localtime(&result));
		tstr = tstr.substr(0, 24);// remove trailling newline
		fprintf(stderr, "%s: %s", tstr.c_str(), msg.c_str());
	}
}


