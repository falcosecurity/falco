/*
Copyright (C) 2019 The Falco Authors.

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

#include <ctime>
#include "logger.h"

#include "falco_common.h"
#include "banned.h" // This raises a compilation error when certain functions are used

int falco_logger::level = LOG_INFO;
bool falco_logger::time_format_iso_8601 = false;

void falco_logger::set_time_format_iso_8601(bool val)
{
	falco_logger::time_format_iso_8601 = val;
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


bool falco_logger::log_stderr = true;
bool falco_logger::log_syslog = true;

void falco_logger::log(int priority, const string msg)
{

	if(priority > falco_logger::level)
	{
		return;
	}

	string copy = msg;

	if (falco_logger::log_syslog)
	{
		// Syslog output should not have any trailing newline
		if(copy.back() == '\n')
		{
			copy.pop_back();
		}

		::syslog(priority, "%s", copy.c_str());
	}

	if (falco_logger::log_stderr)
	{
		// log output should always have a trailing newline
		if(copy.back() != '\n')
		{
			copy.push_back('\n');
		}

		std::time_t result = std::time(nullptr);
		if(falco_logger::time_format_iso_8601)
		{
			char buf[sizeof "YYYY-MM-DDTHH:MM:SS-0000"];
			struct tm *gtm = std::gmtime(&result);
			if(gtm != NULL &&
			   (strftime(buf, sizeof(buf), "%FT%T%z", gtm) != 0))
			{
				fprintf(stderr, "%s: %s", buf, copy.c_str());
			}
		}
		else
		{
			struct tm *ltm = std::localtime(&result);
			char *atime = (ltm ? std::asctime(ltm) : NULL);
			string tstr;
			if(atime)
			{
				tstr = atime;
				tstr = tstr.substr(0, 24);// remove trailling newline
			}
			else
			{
				tstr = "N/A";
			}
			fprintf(stderr, "%s: %s", tstr.c_str(), copy.c_str());
		}
	}
}
