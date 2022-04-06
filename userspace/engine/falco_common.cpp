/*
Copyright (C) 2022 The Falco Authors.

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

vector<string> falco_common::priority_names = {
	"Emergency",
	"Alert",
	"Critical",
	"Error",
	"Warning",
	"Notice",
	"Info",
	"Debug"
};

bool falco_common::parse_priority(string v, priority_type& out)
{
	transform(v.begin(), v.end(), v.begin(), [](int c){return tolower(c);});
	for (size_t i = 0; i < priority_names.size(); i++)
	{
		auto p = priority_names[i];
		transform(p.begin(), p.end(), p.begin(), [](int c){return tolower(c);});
		if (p.compare(0, v.size(), v) == 0)
		{
			out = (priority_type) i;
			return true;
		}
	}
	return false;
}

bool falco_common::format_priority(priority_type v, string& out)
{
	if ((size_t) v < priority_names.size())
	{
		out = priority_names[(size_t) v];
		return true;
	}
	return false;
}
