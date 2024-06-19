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

#include <cstdint>
#include <string>
#if defined(__linux__) and !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__)
#include <arpa/inet.h>
#include <libsinsp/tuples.h>
#endif

namespace falco::utils
{
uint64_t parse_prometheus_interval(std::string interval_str);

#if defined(__linux__) and !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__)
std::string calculate_file_sha256sum(const std::string& filename);
#endif

std::string sanitize_metric_name(const std::string& name);

std::string wrap_text(const std::string& in, uint32_t indent, uint32_t linelen);

void readfile(const std::string& filename, std::string& data);

uint32_t hardware_concurrency();

bool matches_wildcard(const std::string &pattern, const std::string &s);

namespace network
{
static const std::string UNIX_SCHEME("unix://");
bool is_unix_scheme(const std::string& url);
#if defined(__linux__) and !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__)
// todo: consider extending libs and expose API for ipv4 and ipv6 to string conversion
std::string ipv4addr_to_string(uint32_t addr);
std::string ipv6addr_to_string(const ipv6addr& addr);
#endif

} // namespace network
} // namespace falco::utils
