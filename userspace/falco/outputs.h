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
// The way to refer to an output (file, syslog, stdout, etc.)
// An output has a name and set of options.
//
struct config
{
	std::string name;
	std::map<std::string, std::string> options;
};

//
// The message to be outputted. It can either refer to:
//  - an event that has matched some rule,
//  - or a generic message (e.g., a drop alert).
//
struct message
{
	uint64_t ts;
	falco_common::priority_type priority;
	std::string msg;
	std::string rule;
	std::string source;
	map<std::string, std::string> fields;
};

//
// This class acts as the primary interface for implementing
// a Falco output class.
//

class abstract_output
{
public:
	virtual ~abstract_output() {}

	void init(config oc, bool buffered, std::string hostname)
	{
		m_oc = oc;
		m_buffered = buffered;
		m_hostname = hostname;
	}

	// Return the output's name as per its configuration.
	const std::string get_name() const
	{
		return m_oc.name;
	}

	// Output a message.
	virtual void output(const message *msg) = 0;

	// Possibly close the output and open it again.
	virtual void reopen() {}

	// Possibly flush the output.
	virtual void cleanup() {}

protected:
	config m_oc;
	bool m_buffered;
	std::string m_hostname;
};

} // namespace outputs
} // namespace falco
