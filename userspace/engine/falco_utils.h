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

// TODO interim helper methods -> shall be integrated into sinsp APIs
std::unordered_set<uint32_t> get_ppm_sc_set_from_syscalls(const std::unordered_set<std::string>& syscalls);
std::unordered_set<uint32_t> enforce_sinsp_state_ppme(std::unordered_set<uint32_t> ppm_event_info_of_interest = {});
std::unordered_set<uint32_t> enforce_io_ppm_sc_set(std::unordered_set<uint32_t> ppm_sc_set = {}); // needs libs bump hence duplicated in meantime
// end interim helper methods

// TODO interim libs utils methods
template<typename T>
std::set<T> unordered_set_to_ordered(const std::unordered_set<T>& unordered_set);

template<typename T>
std::unordered_set<T> unordered_set_difference(const std::unordered_set<T>& a, const std::unordered_set<T>& b);

template<typename T>
std::set<T> set_difference(const std::set<T>& a, const std::set<T>& b);

template<typename T>
std::unordered_set<T> unordered_set_union(const std::unordered_set<T>& a, const std::unordered_set<T>& b);

template<typename T>
std::set<T> set_union(const std::set<T>& a, const std::set<T>& b);

template<typename T>
std::unordered_set<T> unordered_set_intersection(const std::unordered_set<T>& a, const std::unordered_set<T>& b);

template<typename T>
std::set<T> set_intersection(const std::set<T>& a, const std::set<T>& b);

std::string concat_set_in_order(const std::unordered_set<std::string>& s, const std::string& delim = ", ");
std::string concat_set_in_order(const std::set<std::string>& s, const std::string& delim = ", ");

// end interim libs utils methods

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
