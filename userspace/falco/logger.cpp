#include <ctime>
#include "logger.h"
#include "chisel_api.h"

const static struct luaL_reg ll_falco [] =
{
	{"syslog", &falco_logger::syslog},
	{NULL,NULL}
};


void falco_logger::init(lua_State *ls)
{
	luaL_openlib(ls, "falco", ll_falco, 0);
}

int falco_logger::syslog(lua_State *ls) {
	int priority = luaL_checknumber(ls, 1);

	if (priority > LOG_DEBUG) {
		return luaL_argerror(ls, 1, "falco.syslog: priority must be a number between 0 and 7");
	}

	const char *msg = luaL_checkstring(ls, 2);
	::syslog(priority, "%s", msg);

	return 0;
}

bool falco_logger::log_stderr = true;
bool falco_logger::log_syslog = true;

void falco_logger::log(int priority, const string msg) {
	if (falco_logger::log_syslog) {
		::syslog(priority, "%s", msg.c_str());
	}

	if (falco_logger::log_stderr) {
		std::time_t result = std::time(nullptr);
		string tstr = std::asctime(std::localtime(&result));
		tstr = tstr.substr(0, 24);// remove trailling newline
		fprintf(stderr, "%s: %s", tstr.c_str(), msg.c_str());
	}
}


