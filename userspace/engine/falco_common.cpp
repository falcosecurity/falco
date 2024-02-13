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

#include "falco_common.h"

static std::vector<std::string> priority_names = {
	"Emergency",
	"Alert",
	"Critical",
	"Error",
	"Warning",
	"Notice",
	"Informational",
	"Debug"
};

static std::vector<std::string> rule_matching_names = {
	"first",
	"all"
};

bool falco_common::parse_priority(const std::string& v, priority_type& out)
{
	for (size_t i = 0; i < priority_names.size(); i++)
	{
		// note: for legacy reasons, "Info" and "Informational" has been used
		// interchangeably and ambiguously, so this is the only edge case for
		// which we can't apply strict equality check
		if (!strcasecmp(v.c_str(), priority_names[i].c_str())
			|| (i == PRIORITY_INFORMATIONAL && !strcasecmp(v.c_str(), "info")))
		{
			out = (priority_type) i;
			return true;
		}
	}
	return false;
}

falco_common::priority_type falco_common::parse_priority(const std::string& v)
{
	falco_common::priority_type out;
	if (!parse_priority(v, out))
	{
		throw falco_exception("Unknown priority value: " + v);
	}
	return out;
}

bool falco_common::format_priority(priority_type v, std::string& out, bool shortfmt)
{
	if ((size_t) v < priority_names.size())
	{
		if (v == PRIORITY_INFORMATIONAL && shortfmt)
		{
			out = "Info";
		}
		else
		{
			out = priority_names[(size_t) v];
		}
		return true;
	}
	return false;
}

std::string falco_common::format_priority(priority_type v, bool shortfmt)
{
	std::string out;
	if(!format_priority(v, out, shortfmt))
	{
		throw falco_exception("Unknown priority enum value: " + std::to_string(v));
	}
	return out;
}

bool falco_common::parse_rule_matching(const std::string& v, rule_matching& out)
{
	for (size_t i = 0; i < rule_matching_names.size(); i++)
	{
		if (!strcasecmp(v.c_str(), rule_matching_names[i].c_str()))
		{
			out = (rule_matching) i;
			return true;
		}
	}
	return false;
}
