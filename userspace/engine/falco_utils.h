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

#include <sstream>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <nonstd/string_view.hpp>

#pragma once

namespace falco
{

namespace utils
{

std::string wrap_text(const std::string& str, uint32_t initial_pos, uint32_t indent, uint32_t line_len);

void readfile(const std::string& filename, std::string& data);

uint32_t hardware_concurrency();

namespace network
{
static const std::string UNIX_SCHEME("unix://");
bool is_unix_scheme(nonstd::string_view url);
} // namespace network
} // namespace utils
} // namespace falco
