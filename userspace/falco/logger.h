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

#pragma once

#include <libsinsp/sinsp.h>
#ifndef _WIN32
#include <syslog.h>
#endif

class falco_logger
{
 public:

	 enum class level : int
	{
		EMERG = 0,
		ALERT,
		CRIT,
		ERR,
		WARNING,
		NOTICE,
		INFO,
		DEBUG
	};

	static void set_time_format_iso_8601(bool val);

	// Will throw exception if level is unknown.
	static void set_level(const std::string &level);

	static void set_sinsp_logging(bool enable, const std::string& severity, const std::string& prefix);

	static void log(falco_logger::level priority, const std::string&& msg);

	static level current_level;
	static bool log_stderr;
	static bool log_syslog;
	static bool time_format_iso_8601;
};
