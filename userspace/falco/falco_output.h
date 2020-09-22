/*
Copyright (C) 2020 The Falco Authors.

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

#include <string>
#include <map>

#include "falco_common.h"
#include "gen_filter.h"

namespace falco
{
namespace outputs
{

//
// This class acts as the primary interface for implementing
// a Falco output class.
//

class output
{
public:
	// The way to refer to an output (file, syslog, stdout, etc.)
	// An output has a name and set of options.
	struct config
	{
		std::string name;
		std::map<std::string, std::string> options;
	};

	void init(config oc, bool buffered,
		  bool time_format_iso_8601, std::string hostname)
	{

		m_oc = oc;
		m_buffered = buffered;
		m_time_format_iso_8601 = time_format_iso_8601;
		m_hostname = hostname;
	}

	// Output an event that has matched some rule.
	virtual void output_event(gen_event *evt, std::string &rule, std::string &source,
				  falco_common::priority_type priority, std::string &format, std::string &msg) = 0;

	// Output a generic message. Not necessarily associated with any event.
	virtual void output_msg(falco_common::priority_type priority, std::string &msg) = 0;

	virtual void reopen() {}

	virtual void cleanup() {}

protected:
	config m_oc;
	bool m_buffered;
	bool m_time_format_iso_8601;
	std::string m_hostname;
};

} // namespace outputs
} // namespace falco
