/*
Copyright (C) 2019 The Falco Authors

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

#include "utils.h"
#include "banned.h" // This raises a compilation error when certain functions are used

void falco::utils::read(const std::string& filename, std::string& data)
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

bool falco::utils::starts_with(const std::string& text, const std::string& prefix)
{
	return prefix.empty() ||
	       (text.size() >= prefix.size() &&
		std::memcmp(text.data(), prefix.data(), prefix.size()) == 0);
}

bool falco::utils::network::url_is_unix_scheme(const std::string& url)
{
	return starts_with(url, UNIX_SCHEME);
}
