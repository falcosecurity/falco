/*
Copyright (C) 2016-2018 Draios Inc dba Sysdig.

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

#include "falco_utils.h"

namespace falco
{

namespace utils
{

std::string wrap_text(const std::string &str, uint32_t initial_pos, uint32_t indent, uint32_t line_len)
{
	std::string ret;

	size_t len = str.size();

	for(uint32_t l = 0; l < len; l++)
	{
		if(l % (line_len - indent) == 0 && l != 0)
		{
			ret += "\n";

			for(uint32_t m = 0; m < indent; m++)
			{
				ret += " ";
			}
		}
		ret += str.at(l);
	}

	ret += "\n";

	return ret;
}

} // namespace utils

} // namespace falco
