// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2016-2018 The Falco Authors.

This file is part of falco.

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
#include <cstring>
#include <iomanip>

#include "falco_common.h"
#include "falco_utils.h"
#include "utils.h"

#include <re2/re2.h>

#define RGX_PROMETHEUS_TIME_DURATION "^((?P<y>[0-9]+)y)?((?P<w>[0-9]+)w)?((?P<d>[0-9]+)d)?((?P<h>[0-9]+)h)?((?P<m>[0-9]+)m)?((?P<s>[0-9]+)s)?((?P<ms>[0-9]+)ms)?$"

// using pre-compiled regex
static re2::RE2 s_rgx_prometheus_time_duration(RGX_PROMETHEUS_TIME_DURATION);

// Prometheus time durations: https://prometheus.io/docs/prometheus/latest/querying/basics/#time-durations
#define PROMETHEUS_UNIT_Y "y" ///> assuming a year has always 365d
#define PROMETHEUS_UNIT_W "w" ///> assuming a week has always 7d
#define PROMETHEUS_UNIT_D "d" ///> assuming a day has always 24h
#define PROMETHEUS_UNIT_H "h" ///> hour
#define PROMETHEUS_UNIT_M "m" ///> minute
#define PROMETHEUS_UNIT_S "s" ///> second
#define PROMETHEUS_UNIT_MS "ms" ///> millisecond

// standard time unit conversions to milliseconds
#define ONE_MS_TO_MS 1UL
#define ONE_SECOND_TO_MS 1000UL
#define ONE_MINUTE_TO_MS ONE_SECOND_TO_MS * 60UL
#define ONE_HOUR_TO_MS ONE_MINUTE_TO_MS * 60UL
#define ONE_DAY_TO_MS ONE_HOUR_TO_MS * 24UL
#define ONE_WEEK_TO_MS ONE_DAY_TO_MS * 7UL
#define ONE_YEAR_TO_MS ONE_DAY_TO_MS * 365UL

namespace falco
{

namespace utils
{

uint64_t parse_prometheus_interval(std::string interval_str)
{
	uint64_t interval = 0;
	/* Sanitize user input, remove possible whitespaces. */
	interval_str.erase(remove_if(interval_str.begin(), interval_str.end(), isspace), interval_str.end());

	if(!interval_str.empty())
	{
		re2::StringPiece input(interval_str);
		std::string args[14];
		re2::RE2::Arg arg0(&args[0]);
		re2::RE2::Arg arg1(&args[1]);
		re2::RE2::Arg arg2(&args[2]);
		re2::RE2::Arg arg3(&args[3]);
		re2::RE2::Arg arg4(&args[4]);
		re2::RE2::Arg arg5(&args[5]);
		re2::RE2::Arg arg6(&args[6]);
		re2::RE2::Arg arg7(&args[7]);
		re2::RE2::Arg arg8(&args[8]);
		re2::RE2::Arg arg9(&args[9]);
		re2::RE2::Arg arg10(&args[10]);
		re2::RE2::Arg arg11(&args[11]);
		re2::RE2::Arg arg12(&args[12]);
		re2::RE2::Arg arg13(&args[13]);
		const re2::RE2::Arg* const matches[14] = {&arg0, &arg1, &arg2, &arg3, &arg4, &arg5, &arg6, &arg7, &arg8, &arg9, &arg10, &arg11, &arg12, &arg13};

		const std::map<std::string, int>& named_groups = s_rgx_prometheus_time_duration.NamedCapturingGroups();
		int num_groups = s_rgx_prometheus_time_duration.NumberOfCapturingGroups();
		re2::RE2::FullMatchN(input, s_rgx_prometheus_time_duration, matches, num_groups);

		static const char* all_prometheus_units[7] = {
			PROMETHEUS_UNIT_Y, PROMETHEUS_UNIT_W, PROMETHEUS_UNIT_D, PROMETHEUS_UNIT_H,
			PROMETHEUS_UNIT_M, PROMETHEUS_UNIT_S, PROMETHEUS_UNIT_MS };

		static const uint64_t all_prometheus_time_conversions[7] = {
			ONE_YEAR_TO_MS, ONE_WEEK_TO_MS, ONE_DAY_TO_MS, ONE_HOUR_TO_MS,
			ONE_MINUTE_TO_MS, ONE_SECOND_TO_MS, ONE_MS_TO_MS };

		for(size_t i = 0; i < sizeof(all_prometheus_units) / sizeof(const char*); i++)
		{
			std::string cur_interval_str;
			uint64_t cur_interval = 0;
			const auto &group_it = named_groups.find(all_prometheus_units[i]);
			if(group_it != named_groups.end())
			{
				cur_interval_str = args[group_it->second - 1];
				if(!cur_interval_str.empty())
				{
					cur_interval = std::stoull(cur_interval_str, nullptr, 0);
				}
				if(cur_interval > 0)
				{
					interval += cur_interval * all_prometheus_time_conversions[i];
				}
			}
		}
	}
	return interval;
}

std::string wrap_text(const std::string& in, uint32_t indent, uint32_t line_len)
{
	std::istringstream is(in);
	std::ostringstream os;
	std::string word;
	uint32_t len = 0;
	while (is >> word)
	{
		if((len + word.length() + 1) <= (line_len-indent))
		{
			len += word.length() + 1;
		}
		else
		{
			os << std::endl;
			os << std::left << std::setw(indent) << " ";
			len = word.length() + 1;
		}
		os << word << " ";
	}
	return os.str();
}

uint32_t hardware_concurrency()
{
	auto hc = std::thread::hardware_concurrency();
	return hc ? hc : 1;
}

void readfile(const std::string& filename, std::string& data)
{
	std::ifstream file(filename.c_str(), std::ios::in);

	if(file.is_open())
	{
		std::stringstream ss;
		ss << file.rdbuf();

		file.close();

		data = ss.str();
	}

	return;
}

// URI-decodes the given string by replacing percent-encoded
// characters with the actual character. Returns the decoded string.
//
// When plus_as_space is true, non-encoded plus signs in the query are decoded as spaces.
// (http://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.1)
std::string decode_uri(const std::string& str, bool plus_as_space)
{
	std::string decoded_str;
	bool in_query = false;
	std::string::const_iterator it  = str.begin();
	std::string::const_iterator end = str.end();
	while(it != end)
	{
		char c = *it++;
		if(c == '?')
		{
			in_query = true;
		}
		// spaces may be encoded as plus signs in the query
		if(in_query && plus_as_space && c == '+')
		{
			c = ' ';
		}
		else if(c == '%')
		{
			if (it == end)
			{
				throw falco_exception("URI encoding: no hex digit following percent sign in " + str);
			}
			char hi = *it++;
			if (it == end)
			{
				throw falco_exception("URI encoding: two hex digits must follow percent sign in " + str);
			}
			char lo = *it++;
			if (hi >= '0' && hi <= '9')
			{
				c = hi - '0';
			}
			else if (hi >= 'A' && hi <= 'F')
			{
				c = hi - 'A' + 10;
			}
			else if (hi >= 'a' && hi <= 'f')
			{
				c = hi - 'a' + 10;
			}
			else
			{
				throw falco_exception("URI encoding: not a hex digit found in " + str);
			}
			c *= 16;
			if (lo >= '0' && lo <= '9')
			{
				c += lo - '0';
			}
			else if (lo >= 'A' && lo <= 'F')
			{
				c += lo - 'A' + 10;
			}
			else if (lo >= 'a' && lo <= 'f')
			{
				c += lo - 'a' + 10;
			}
			else
			{
				throw falco_exception("URI encoding: not a hex digit");
			}
		}
		decoded_str += c;
	}
	return decoded_str;
}

namespace network
{
bool is_unix_scheme(const std::string& url)
{
	return sinsp_utils::startswith(url, UNIX_SCHEME);
}
} // namespace network
} // namespace utils
} // namespace falco
