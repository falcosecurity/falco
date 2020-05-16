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

#pragma once

#include <sstream>
#include <fstream>
#include <iostream>
#include <string>

namespace falco
{
namespace utils
{
void read(const std::string& filename, std::string& data);
bool starts_with(const std::string& text, const std::string& prefix);

namespace network
{
static const std::string UNIX_SCHEME{"unix://"};
bool url_is_unix_scheme(const std::string& url);
} // namespace network
} // namespace utils
} // namespace falco
