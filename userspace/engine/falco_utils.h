// SPDX-License-Identifier: Apache-2.0
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

#pragma once

#include <sstream>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <unordered_set>
#include <set>
#include <vector>
#include <string>

#ifdef __GNUC__
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

namespace falco
{

namespace utils
{

uint64_t parse_prometheus_interval(std::string interval_str);

std::string wrap_text(const std::string& in, uint32_t indent, uint32_t linelen);

void readfile(const std::string& filename, std::string& data);

uint32_t hardware_concurrency();

namespace network
{
static const std::string UNIX_SCHEME("unix://");
bool is_unix_scheme(const std::string& url);
} // namespace network
} // namespace utils
} // namespace falco
