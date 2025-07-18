// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#include "../state.h"
#include "../run_result.h"

#include <string>
#include <nlohmann/json.hpp>

namespace falco {
namespace app {
namespace actions {

bool check_rules_plugin_requirements(falco::app::state& s, std::string& err);
void print_enabled_event_sources(falco::app::state& s);
void activate_interesting_kernel_tracepoints(falco::app::state& s,
                                             std::unique_ptr<sinsp>& inspector);
void check_for_ignored_events(falco::app::state& s);
void format_plugin_info(std::shared_ptr<sinsp_plugin> p, std::ostream& os);
void format_described_rules_as_text(const nlohmann::json& v, std::ostream& os);

inline std::string generate_scap_file_path(const std::string& prefix,
                                           uint64_t timestamp,
                                           uint64_t evt_num) {
	// File path in format: <prefix>_<timestamp>_<evt_num>.scap
	// Example: "/tmp/falco_00000001234567890_00000000000000042.scap"

	// Add underscore separator between prefix and timestamp
	std::string path = prefix + "_";

	// Zero-pad timestamp to 20 digits for proper lexicographic sorting
	// Build digits from right to left in a buffer, then append to path
	char digits[21];  // 20 digits + null terminator
	digits[20] = '\0';
	uint64_t t = timestamp;
	for(int i = 19; i >= 0; --i) {
		digits[i] = '0' + (t % 10);
		t /= 10;
	}
	path += digits;

	// Add underscore separator between timestamp and evt_num
	path += "_";

	// Zero-pad evt_num to 20 digits for proper lexicographic sorting
	// Build digits from right to left in a buffer, then append to path
	t = evt_num;
	for(int i = 19; i >= 0; --i) {
		digits[i] = '0' + (t % 10);
		t /= 10;
	}
	path += digits;

	// Add file extension
	path += ".scap";

	return path;
}

falco::app::run_result open_offline_inspector(falco::app::state& s);
falco::app::run_result open_live_inspector(falco::app::state& s,
                                           std::shared_ptr<sinsp> inspector,
                                           const std::string& source);

template<class InputIterator>
void read_files(InputIterator begin,
                InputIterator end,
                std::vector<std::string>& rules_contents,
                falco::load_result::rules_contents_t& rc) {
	// Read the contents in a first pass
	for(auto it = begin; it != end; it++) {
		const std::string& filename = *it;
		std::ifstream is;
		is.open(filename);
		if(!is.is_open()) {
			throw falco_exception("Could not open file " + filename + " for reading");
		}

		std::string rules_content((std::istreambuf_iterator<char>(is)),
		                          std::istreambuf_iterator<char>());
		rules_contents.emplace_back(std::move(rules_content));
	}

	// Populate the map in a second pass to avoid
	// references becoming invalid.
	auto it = begin;
	auto rit = rules_contents.begin();
	for(; it != end && rit != rules_contents.end(); it++, rit++) {
		rc.emplace(*it, *rit);
	}

	// Both it and rit must be at the end, otherwise
	// there's a bug in the above
	if(it != end || rit != rules_contents.end()) {
		throw falco_exception("Unexpected mismatch in rules content name/rules content sets?");
	}
}

};  // namespace actions
};  // namespace app
};  // namespace falco
