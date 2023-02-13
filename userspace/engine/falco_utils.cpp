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
#include <cstring>
#include <iomanip>
#include <unordered_set>
#include <set>
#include <iterator>
#include <string>
#include <vector>
#include <sinsp.h>

#include "falco_utils.h"
#include "utils.h"
#include "banned.h" // This raises a compilation error when certain functions are used

extern sinsp_evttables g_infotables;

namespace falco
{

namespace utils
{

std::unordered_set<uint32_t> get_ppm_sc_set_from_syscalls(const std::unordered_set<std::string>& syscalls)
{
	std::unordered_set<uint32_t> ppm_sc_set = {};
	for (int ppm_sc_code = 0; ppm_sc_code < PPM_SC_MAX; ++ppm_sc_code)
	{
		std::string ppm_sc_name = g_infotables.m_syscall_info_table[ppm_sc_code].name;
		if (syscalls.find(ppm_sc_name) != syscalls.end())
		{
			ppm_sc_set.insert(ppm_sc_code);
		}
	}
	return ppm_sc_set;
}

std::unordered_set<uint32_t> enforce_io_ppm_sc_set(std::unordered_set<uint32_t> ppm_sc_set)
{
	const int bitmask = EC_SYSCALL - 1;
	for(int ppm_sc_code = 0; ppm_sc_code < PPM_SC_MAX; ppm_sc_code++)
	{
		switch(g_infotables.m_syscall_info_table[ppm_sc_code].category & bitmask)
		{
		case EC_IO_READ:
		case EC_IO_WRITE:
			ppm_sc_set.insert(ppm_sc_code);
		}
	}
	return ppm_sc_set;
}

std::unordered_set<uint32_t> enforce_sinsp_state_ppme(std::unordered_set<uint32_t> ppm_event_info_of_interest)
{
	/* Fill-up the set of event infos of interest. This is needed to ensure critical non syscall PPME events are activated, e.g. container or proc exit events. */
	for (uint32_t ev = 2; ev < PPM_EVENT_MAX; ev++)
	{
		if (!sinsp::is_old_version_event(ev)
				&& !sinsp::is_unused_event(ev)
				&& !sinsp::is_unknown_event(ev))
		{
			/* So far we only covered syscalls, so we add other kinds of
			interesting events. In this case, we are also interested in
			metaevents and in the procexit tracepoint event. */
			if (sinsp::is_metaevent(ev) || ev == PPME_PROCEXIT_1_E)
			{
				ppm_event_info_of_interest.insert(ev);
			}
		}
	}
	return ppm_event_info_of_interest;
}

// unordered_set_to_ordered
template<typename T>
std::set<T> unordered_set_to_ordered(const std::unordered_set<T>& unordered_set)
{
	std::set<T> s;
	for(const auto& val : unordered_set)
	{
		s.insert(val);
	}
	return s;
}
template std::set<uint32_t> unordered_set_to_ordered(const std::unordered_set<uint32_t>& unordered_set);
template std::set<std::string> unordered_set_to_ordered(const std::unordered_set<std::string>& unordered_set);

// unordered_set_difference, equivalent to SQL left_anti join operation
template<typename T>
std::unordered_set<T> unordered_set_difference(const std::unordered_set<T>& a, const std::unordered_set<T>& b)
{
	std::unordered_set<T> s;
	for(const auto& val : a)
	{
		if (b.find(val) == b.end())
		{
			s.insert(val);
		}
	}
	return s;
}
template std::unordered_set<std::string> unordered_set_difference(const std::unordered_set<std::string>& a, const std::unordered_set<std::string>& b);
template std::unordered_set<uint32_t> unordered_set_difference(const std::unordered_set<uint32_t>& a, const std::unordered_set<uint32_t>& b);

// set_difference, equivalent to SQL left_anti join operation
template<typename T>
std::set<T> set_difference(const std::set<T>& a, const std::set<T>& b)
{
	std::set<T> out;
	std::set_difference(a.begin(), a.end(), b.begin(), b.end(), std::inserter(out, out.begin()));
	return out;
}
template std::set<std::string> set_difference(const std::set<std::string>& a, const std::set<std::string>& b);
template std::set<uint32_t> set_difference(const std::set<uint32_t>& a, const std::set<uint32_t>& b);

// unordered_set_union
template<typename T>
std::unordered_set<T> unordered_set_union(const std::unordered_set<T>& a, const std::unordered_set<T>& b)
{
	std::unordered_set<T> s = a;
	for(const auto& val : b)
	{
		s.insert(val);
	}
	return s;
}
template std::unordered_set<std::string> unordered_set_union(const std::unordered_set<std::string>& a, const std::unordered_set<std::string>& b);
template std::unordered_set<uint32_t> unordered_set_union(const std::unordered_set<uint32_t>& a, const std::unordered_set<uint32_t>& b);

// set_union
template<typename T>
std::set<T> set_union(const std::set<T>& a, const std::set<T>& b)
{
	std::set<T> out;
	std::set_union(a.begin(), a.end(), b.begin(), b.end(), std::inserter(out, out.begin()));
	return out;
}
template std::set<std::string> set_union(const std::set<std::string>& a, const std::set<std::string>& b);
template std::set<uint32_t> set_union(const std::set<uint32_t>& a, const std::set<uint32_t>& b);

// unordered_set_intersection
template<typename T>
std::unordered_set<T> unordered_set_intersection(const std::unordered_set<T>& a, const std::unordered_set<T>& b)
{
	std::unordered_set<T> s;
	for(const auto& val : a)
	{
		if (b.find(val) != b.end())
		{
			s.insert(val);
		}
	}
	return s;
}
template std::unordered_set<std::string> unordered_set_intersection(const std::unordered_set<std::string>& a, const std::unordered_set<std::string>& b);
template std::unordered_set<uint32_t> unordered_set_intersection(const std::unordered_set<uint32_t>& a, const std::unordered_set<uint32_t>& b);

// set_intersection
template<typename T>
std::set<T> set_intersection(const std::set<T>& a, const std::set<T>& b)
{
	std::set<T> out;
	std::set_intersection(a.begin(), a.end(), b.begin(), b.end(), std::inserter(out, out.begin()));
	return out;
}
template std::set<std::string> set_intersection(const std::set<std::string>& a, const std::set<std::string>& b);
template std::set<uint32_t> set_intersection(const std::set<uint32_t>& a, const std::set<uint32_t>& b);

std::string concat_set_in_order(const std::unordered_set<std::string>& s, const std::string& delim)
{
	if (s.empty())
	{
		return "";
	}
	std::set<std::string> s_ordered = unordered_set_to_ordered(s);
	std::stringstream ss;
	std::copy(s_ordered.begin(), s_ordered.end(),
	std::ostream_iterator<std::string>(ss, delim.c_str()));
	std::string s_str = ss.str();
	return s_str.substr(0, s_str.size() - delim.size());
}

std::string concat_set_in_order(const std::set<std::string>& s, const std::string& delim)
{
	if (s.empty())
	{
		return "";
	}
	std::stringstream ss;
	std::copy(s.begin(), s.end(),
	std::ostream_iterator<std::string>(ss, delim.c_str()));
	std::string s_str = ss.str();
	return s_str.substr(0, s_str.size() - delim.size());
}


std::string wrap_text(const std::string& in, uint32_t indent, uint32_t line_len)
{
	std::istringstream is(in);
	std::ostringstream os;
	std::string word;
	uint32_t len = 0;
	while (is >> word)
	{
		if((len + word.length() + 1) <= (line_len-indent))
		{
			len += word.length() + 1;
		}
		else
		{
			os << std::endl;
			os << std::left << std::setw(indent) << " ";
			len = word.length() + 1;
		}
		os << word << " ";
	}
	return os.str();
}

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
bool is_unix_scheme(const std::string& url)
{
	return sinsp_utils::startswith(url, UNIX_SCHEME);
}
} // namespace network
} // namespace utils
} // namespace falco
