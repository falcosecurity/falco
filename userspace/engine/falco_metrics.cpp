/*
Copyright (C) 2023 The Falco Authors.

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

#include "falco_utils.h"
#include "utils.h"
#include "banned.h" // This raises a compilation error when certain functions are used

#include <re2/re2.h>

// these follow the POSIX standard
#define RGX_PROMETHEUS_TIME_DURATION_PATTERN "([0-9]+[a-z]+)"
#define RGX_PROMETHEUS_NUMBER_PATTERN "([0-9]+)"
#define RGX_PROMETHEUS_UNIT_PATTERN "([a-z]+)"

// using pre-compiled regex for better performance
static re2::RE2 s_rgx_prometheus_time_duration(RGX_PROMETHEUS_TIME_DURATION_PATTERN, re2::RE2::POSIX);
static re2::RE2 s_rgx_prometheus_number(RGX_PROMETHEUS_NUMBER_PATTERN, re2::RE2::POSIX);
static re2::RE2 s_rgx_prometheus_unit(RGX_PROMETHEUS_UNIT_PATTERN, re2::RE2::POSIX);

// Prometheus time durations: https://prometheus.io/docs/prometheus/latest/querying/basics/#time-durations
#define PROMETHEUS_UNIT_Y "y" ///> assuming a year has always 365d
#define PROMETHEUS_UNIT_W "w" ///> assuming a week has always 7d
#define PROMETHEUS_UNIT_D "d" ///> assuming a day has always 24h
#define PROMETHEUS_UNIT_H "h" ///> hour
#define PROMETHEUS_UNIT_M "m" ///> minute
#define PROMETHEUS_UNIT_S "s" ///> second
#define PROMETHEUS_UNIT_MS "ms" ///> millisecond

// standard time unit conversions to milliseconds
#define SECOND_TO_MS 1000
#define MINUTE_TO_MS SECOND_TO_MS * 60
#define HOUR_TO_MS MINUTE_TO_MS * 60
#define DAY_TO_MS HOUR_TO_MS * 24
#define WEEK_TO_MS DAY_TO_MS * 7
#define YEAR_TO_MS DAY_TO_MS * 365

namespace falco
{
namespace metrics
{

uint64_t parse_metrics_interval(std::string interval_str)
{
    uint64_t interval = 0;
    /* Sanitize user input, remove possible whitespaces. */
    interval_str.erase(remove_if(interval_str.begin(), interval_str.end(), isspace), interval_str.end());

    if(!interval_str.empty())
	{
        /* Option 1: Passing interval directly in ms. Will be deprecated in the future. */
        if(std::all_of(interval_str.begin(), interval_str.end(), ::isdigit))
        {
            /* todo: deprecate for Falco 0.36. */
            interval = std::stoull(interval_str, nullptr, 0);
            std::cerr << "Metrics interval was passed as numeric value without Prometheus time unit, this option will no longer be supported starting Falco 0.36" << std::endl;
        }
        /* Option 2: Passing a Prometheus time duration. 
         * https://prometheus.io/docs/prometheus/latest/querying/basics/#time-durations
        */
        else
        {
            re2::StringPiece input(interval_str);
            std::string r;
            std::string cur_interval_str;
            uint64_t cur_interval;
            std::string cur_unit;
            bool valid = true;
            /* Note that parsing is done at start up only. */
            while(re2::RE2::FindAndConsume(&input, s_rgx_prometheus_time_duration, &r))
            {
                RE2::Extract(r, s_rgx_prometheus_number, "\\1", &cur_interval_str);
                cur_interval = std::stoull(cur_interval_str, nullptr, 0);
                if(cur_interval > 0)
                {
                    RE2::Extract(r, s_rgx_prometheus_unit, "\\1", &cur_unit);
                    if(cur_unit == PROMETHEUS_UNIT_MS)
                    {
                        interval += cur_interval;
                    }
                    else if(cur_unit == PROMETHEUS_UNIT_S)
                    {
                        interval += cur_interval * SECOND_TO_MS;
                    }
                    else if(cur_unit == PROMETHEUS_UNIT_M)
                    {
                        interval += cur_interval * MINUTE_TO_MS;
                    }
                    else if(cur_unit == PROMETHEUS_UNIT_H)
                    {
                        interval += cur_interval * HOUR_TO_MS;
                    }
                    else if(cur_unit == PROMETHEUS_UNIT_D)
                    {
                        interval += cur_interval * DAY_TO_MS;
                    }
                    else if(cur_unit == PROMETHEUS_UNIT_W)
                    {
                        interval += cur_interval * WEEK_TO_MS;
                    }
                    else if(cur_unit == PROMETHEUS_UNIT_Y)
                    {
                        interval += cur_interval * YEAR_TO_MS;
                    }
                    else
                    {
                        valid = false;
                    }
                }
                else
                {
                    valid = false;
                }
            }
            if (!valid)
            {
                // invalidate if any invalid unit or no corresponding numeric value was found
                interval = 0;
            }
        }
    }

    return interval;
}


} // namespace metrics
} // namespace falco