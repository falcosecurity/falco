/*
Copyright (C) 2016 Draios inc.

This file is part of falco.

falco is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

falco is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with falco.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ctime>
#include "logger.h"
#include "chisel_api.h"

#include "falco_common.h"

const static struct luaL_reg ll_falco [] =
{
	{"syslog", &falco_logger::syslog},
	{NULL,NULL}
};

int falco_logger::level = LOG_INFO;

void falco_logger::init(lua_State *ls)
{
	luaL_openlib(ls, "falco", ll_falco, 0);
}

void falco_logger::set_level(string &level)
{
	if(level == "emergency")
	{
		falco_logger::level = LOG_EMERG;
	}
	else if(level == "alert")
	{
		falco_logger::level = LOG_ALERT;
	}
	else if(level == "critical")
	{
		falco_logger::level = LOG_CRIT;
	}
	else if(level == "error")
	{
		falco_logger::level = LOG_ERR;
	}
	else if(level == "warning")
	{
		falco_logger::level = LOG_WARNING;
	}
	else if(level == "notice")
	{
		falco_logger::level = LOG_NOTICE;
	}
	else if(level == "info")
	{
		falco_logger::level = LOG_INFO;
	}
	else if(level == "debug")
	{
		falco_logger::level = LOG_DEBUG;
	}
	else
	{
		throw falco_exception("Unknown log level " + level);
	}
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

	if(priority > falco_logger::level)
	{
		return;
	}

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


