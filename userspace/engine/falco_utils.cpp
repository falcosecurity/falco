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

#include "falco_utils.h"
#include "banned.h" // This raises a compilation error when certain functions are used

namespace falco
{

namespace utils
{

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
namespace network
{
bool is_unix_scheme(nonstd::string_view url)
{
	return url.starts_with(UNIX_SCHEME);
}
} // namespace network
} // namespace utils
} // namespace falco
