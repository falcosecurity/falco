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

#include "falco_utils.h"
#include <libsinsp/utils.h>

#include <re2/re2.h>
#if defined(__linux__) and !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__)
#include <openssl/evp.h>
#endif
#include <cstring>
#include <fstream>
#include <iomanip>
#include <thread>

#define RGX_PROMETHEUS_TIME_DURATION                                                              \
	"^((?P<y>[0-9]+)y)?((?P<w>[0-9]+)w)?((?P<d>[0-9]+)d)?((?P<h>[0-9]+)h)?((?P<m>[0-9]+)m)?((?P<" \
	"s>[0-9]+)s)?((?P<ms>[0-9]+)ms)?$"

// using pre-compiled regex
static re2::RE2 s_rgx_prometheus_time_duration(RGX_PROMETHEUS_TIME_DURATION);

// Prometheus time durations:
// https://prometheus.io/docs/prometheus/latest/querying/basics/#time-durations
#define PROMETHEUS_UNIT_Y "y"    ///> assuming a year has always 365d
#define PROMETHEUS_UNIT_W "w"    ///> assuming a week has always 7d
#define PROMETHEUS_UNIT_D "d"    ///> assuming a day has always 24h
#define PROMETHEUS_UNIT_H "h"    ///> hour
#define PROMETHEUS_UNIT_M "m"    ///> minute
#define PROMETHEUS_UNIT_S "s"    ///> second
#define PROMETHEUS_UNIT_MS "ms"  ///> millisecond

// standard time unit conversions to milliseconds
#define ONE_MS_TO_MS 1UL
#define ONE_SECOND_TO_MS 1000UL
#define ONE_MINUTE_TO_MS ONE_SECOND_TO_MS * 60UL
#define ONE_HOUR_TO_MS ONE_MINUTE_TO_MS * 60UL
#define ONE_DAY_TO_MS ONE_HOUR_TO_MS * 24UL
#define ONE_WEEK_TO_MS ONE_DAY_TO_MS * 7UL
#define ONE_YEAR_TO_MS ONE_DAY_TO_MS * 365UL

namespace falco {

namespace utils {

uint64_t parse_prometheus_interval(std::string interval_str) {
	uint64_t interval = 0;
	/* Sanitize user input, remove possible whitespaces. */
	interval_str.erase(remove_if(interval_str.begin(), interval_str.end(), isspace),
	                   interval_str.end());

	if(!interval_str.empty()) {
		re2::StringPiece input(interval_str);
		std::string args[14];
		re2::RE2::Arg arg0(&args[0]);
		re2::RE2::Arg arg1(&args[1]);
		re2::RE2::Arg arg2(&args[2]);
		re2::RE2::Arg arg3(&args[3]);
		re2::RE2::Arg arg4(&args[4]);
		re2::RE2::Arg arg5(&args[5]);
		re2::RE2::Arg arg6(&args[6]);
		re2::RE2::Arg arg7(&args[7]);
		re2::RE2::Arg arg8(&args[8]);
		re2::RE2::Arg arg9(&args[9]);
		re2::RE2::Arg arg10(&args[10]);
		re2::RE2::Arg arg11(&args[11]);
		re2::RE2::Arg arg12(&args[12]);
		re2::RE2::Arg arg13(&args[13]);
		const re2::RE2::Arg* const matches[14] = {&arg0,
		                                          &arg1,
		                                          &arg2,
		                                          &arg3,
		                                          &arg4,
		                                          &arg5,
		                                          &arg6,
		                                          &arg7,
		                                          &arg8,
		                                          &arg9,
		                                          &arg10,
		                                          &arg11,
		                                          &arg12,
		                                          &arg13};

		const std::map<std::string, int>& named_groups =
		        s_rgx_prometheus_time_duration.NamedCapturingGroups();
		int num_groups = s_rgx_prometheus_time_duration.NumberOfCapturingGroups();
		re2::RE2::FullMatchN(input, s_rgx_prometheus_time_duration, matches, num_groups);

		static const char* all_prometheus_units[7] = {PROMETHEUS_UNIT_Y,
		                                              PROMETHEUS_UNIT_W,
		                                              PROMETHEUS_UNIT_D,
		                                              PROMETHEUS_UNIT_H,
		                                              PROMETHEUS_UNIT_M,
		                                              PROMETHEUS_UNIT_S,
		                                              PROMETHEUS_UNIT_MS};

		static const uint64_t all_prometheus_time_conversions[7] = {ONE_YEAR_TO_MS,
		                                                            ONE_WEEK_TO_MS,
		                                                            ONE_DAY_TO_MS,
		                                                            ONE_HOUR_TO_MS,
		                                                            ONE_MINUTE_TO_MS,
		                                                            ONE_SECOND_TO_MS,
		                                                            ONE_MS_TO_MS};

		for(size_t i = 0; i < sizeof(all_prometheus_units) / sizeof(const char*); i++) {
			const auto& group_it = named_groups.find(all_prometheus_units[i]);
			if(group_it != named_groups.end()) {
				uint64_t cur_interval = 0;
				std::string cur_interval_str = args[group_it->second - 1];
				if(!cur_interval_str.empty()) {
					cur_interval = std::stoull(cur_interval_str, nullptr, 0);
				}
				if(cur_interval > 0) {
					interval += cur_interval * all_prometheus_time_conversions[i];
				}
			}
		}
	}
	return interval;
}

#if defined(__linux__) and !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__)
std::string calculate_file_sha256sum(const std::string& filename) {
	std::ifstream file(filename, std::ios::binary);
	if(!file.is_open()) {
		return "";
	}

	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr);

	constexpr size_t buffer_size = 4096;
	char buffer[buffer_size];
	while(file.read(buffer, buffer_size)) {
		EVP_DigestUpdate(ctx.get(), buffer, buffer_size);
	}
	EVP_DigestUpdate(ctx.get(), buffer, file.gcount());

	std::vector<uint8_t> digest(EVP_MD_size(EVP_sha256()));
	EVP_DigestFinal_ex(ctx.get(), digest.data(), nullptr);

	std::ostringstream ss;
	for(auto& c : digest) {
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
	}
	return ss.str();
}
#endif

std::string sanitize_rule_name(const std::string& name) {
	std::string sanitized_name = name;
	RE2::GlobalReplace(&sanitized_name, "[^a-zA-Z0-9_:]", "_");
	RE2::GlobalReplace(&sanitized_name, "_+", "_");
	if(!sanitized_name.empty() && sanitized_name.back() == '_') {
		sanitized_name.pop_back();
	}
	return sanitized_name;
}

std::string wrap_text(const std::string& in, uint32_t indent, uint32_t line_len) {
	std::istringstream is(in);
	std::ostringstream os;
	std::string word;
	uint32_t len = 0;
	while(is >> word) {
		if((len + word.length() + 1) <= (line_len - indent)) {
			len += word.length() + 1;
		} else {
			os << std::endl;
			os << std::left << std::setw(indent) << " ";
			len = word.length() + 1;
		}
		os << word << " ";
	}
	return os.str();
}

uint32_t hardware_concurrency() {
	auto hc = std::thread::hardware_concurrency();
	return hc ? hc : 1;
}

void readfile(const std::string& filename, std::string& data) {
	std::ifstream file(filename, std::ios::in);

	if(file.is_open()) {
		std::stringstream ss;
		ss << file.rdbuf();

		file.close();

		data = ss.str();
	}

	return;
}

bool matches_wildcard(const std::string& pattern, const std::string& s) {
	std::string::size_type star_pos = pattern.find("*");
	if(star_pos == std::string::npos) {
		// regular match (no wildcards)
		return pattern == s;
	}

	if(star_pos == 0) {
		// wildcard at the beginning "*something*..."

		std::string::size_type next_pattern_start = pattern.find_first_not_of("*");
		if(next_pattern_start == std::string::npos) {
			// pattern was just a sequence of stars *, **, ***, ... . This always matches.
			return true;
		}

		std::string next_pattern = pattern.substr(next_pattern_start);
		std::string to_find = next_pattern.substr(0, next_pattern.find("*"));
		std::string::size_type lit_pos = s.find(to_find);
		if(lit_pos == std::string::npos) {
			return false;
		}

		return matches_wildcard(next_pattern.substr(to_find.size()),
		                        s.substr(lit_pos + to_find.size()));
	} else {
		// wildcard at the end or in the middle "something*else*..."

		if(pattern.substr(0, star_pos) != s.substr(0, star_pos)) {
			return false;
		}

		return matches_wildcard(pattern.substr(star_pos), s.substr(star_pos));
	}
}

namespace network {
bool is_unix_scheme(const std::string& url) {
	return sinsp_utils::startswith(url, UNIX_SCHEME);
}
}  // namespace network
}  // namespace utils
}  // namespace falco
