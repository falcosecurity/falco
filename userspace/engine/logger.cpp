// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

falco_logger::level falco_logger::current_level = falco_logger::level::INFO;
bool falco_logger::time_format_iso_8601 = false;

static sinsp_logger::severity decode_sinsp_severity(const std::string& s)
{
	if(s == "trace")
	{
		return sinsp_logger::SEV_TRACE;
	}
	else if(s == "debug")
	{
		return sinsp_logger::SEV_DEBUG;
	}
	else if(s == "info")
	{
		return sinsp_logger::SEV_INFO;
	}
	else if(s == "notice")
	{
		return sinsp_logger::SEV_NOTICE;
	}
	else if(s == "warning")
	{
		return sinsp_logger::SEV_WARNING;
	}
	else if(s == "error")
	{
		return sinsp_logger::SEV_ERROR;
	}
	else if(s == "critical")
	{
		return sinsp_logger::SEV_CRITICAL;
	}
	else if(s == "fatal")
	{
		return sinsp_logger::SEV_FATAL;
	}
	throw falco_exception("Unknown sinsp log severity " + s);
}

void falco_logger::set_time_format_iso_8601(bool val)
{
	falco_logger::time_format_iso_8601 = val;
}

void falco_logger::set_level(const std::string &level)
{
	if(level == "emergency")
	{
		falco_logger::current_level = falco_logger::level::EMERG;
	}
	else if(level == "alert")
	{
		falco_logger::current_level = falco_logger::level::ALERT;
	}
	else if(level == "critical")
	{
		falco_logger::current_level = falco_logger::level::CRIT;
	}
	else if(level == "error")
	{
		falco_logger::current_level = falco_logger::level::ERR;
	}
	else if(level == "warning")
	{
		falco_logger::current_level = falco_logger::level::WARNING;
	}
	else if(level == "notice")
	{
		falco_logger::current_level = falco_logger::level::NOTICE;
	}
	else if(level == "info")
	{
		falco_logger::current_level = falco_logger::level::INFO;
	}
	else if(level == "debug")
	{
		falco_logger::current_level = falco_logger::level::DEBUG;
	}
	else
	{
		throw falco_exception("Unknown log level " + level);
	}
}

static std::string s_sinsp_logger_prefix = "";

void falco_logger::set_sinsp_logging(bool enable, const std::string& severity, const std::string& prefix)
{
	if (enable)
	{
		s_sinsp_logger_prefix = prefix;
		libsinsp_logger()->set_severity(decode_sinsp_severity(severity));
		libsinsp_logger()->disable_timestamps();
		libsinsp_logger()->add_callback_log(
			[](std::string&& str, const sinsp_logger::severity sev)
			{
				// note: using falco_logger::level ensures that the sinsp
				// logs are always printed by the Falco logger. These
				// logs are pre-filtered at the sinsp level depending
				// on the configured severity
				falco_logger::log(falco_logger::current_level, s_sinsp_logger_prefix + str);
			});
	}
	else
	{
		libsinsp_logger()->remove_callback_log();
	}
}


bool falco_logger::log_stderr = true;
bool falco_logger::log_syslog = true;

void falco_logger::log(falco_logger::level priority, const std::string&& msg)
{

	if(priority > falco_logger::current_level)
	{
		return;
	}

	std::string copy = msg;

#ifndef _WIN32
	if (falco_logger::log_syslog)
	{
		// Syslog output should not have any trailing newline
		if(copy.back() == '\n')
		{
			copy.pop_back();
		}

		::syslog(static_cast<int>(priority), "%s", copy.c_str());
	}
#endif

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
			const struct tm *gtm = std::gmtime(&result);
			if(gtm != NULL &&
			   (strftime(buf, sizeof(buf), "%FT%T%z", gtm) != 0))
			{
				fprintf(stderr, "%s: %s", buf, copy.c_str());
			}
		}
		else
		{
			const struct tm *ltm = std::localtime(&result);
			char *atime = (ltm ? std::asctime(ltm) : NULL);
			std::string tstr;
			if(atime)
			{
				tstr = atime;
				tstr = tstr.substr(0, 24);// remove trailing newline
			}
			else
			{
				tstr = "N/A";
			}
			fprintf(stderr, "%s: %s", tstr.c_str(), copy.c_str());
		}
	}
}
