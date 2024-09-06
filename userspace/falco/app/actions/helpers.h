// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <nlohmann/json.hpp>

namespace falco {
namespace app {
namespace actions {

// Map that holds { rule filename | validation status } for each rule file read.
typedef std::map<std::string, std::string> rule_read_res;

bool check_rules_plugin_requirements(falco::app::state& s, std::string& err);
void print_enabled_event_sources(falco::app::state& s);
void activate_interesting_kernel_tracepoints(falco::app::state& s, std::unique_ptr<sinsp>& inspector);
void check_for_ignored_events(falco::app::state& s);
void format_plugin_info(std::shared_ptr<sinsp_plugin> p, std::ostream& os);
void format_described_rules_as_text(const nlohmann::json& v, std::ostream& os);

falco::app::run_result open_offline_inspector(falco::app::state& s);
falco::app::run_result open_live_inspector(
    falco::app::state& s,
    std::shared_ptr<sinsp> inspector,
    const std::string& source);

template<class InputIterator>
rule_read_res read_files(InputIterator begin, InputIterator end,
		std::vector<std::string>& rules_contents,
		falco::load_result::rules_contents_t& rc,
		const nlohmann::json& schema={})
{
	rule_read_res res;
	yaml_helper reader;
	std::string validation;
	// Read the contents in a first pass
	for(auto it = begin; it != end; it++)
	{
		const std::string &filename = *it;
		std::ifstream is;
		is.open(filename);
		if (!is.is_open())
		{
			throw falco_exception("Could not open file " + filename + " for reading");
		}

		std::string rules_content((std::istreambuf_iterator<char>(is)),
						std::istreambuf_iterator<char>());

		reader.load_from_string(rules_content, schema, &validation);
		res[filename] = validation;
		rules_contents.emplace_back(std::move(rules_content));
	}

	// Populate the map in a second pass to avoid
	// references becoming invalid.
	auto it = begin;
	auto rit = rules_contents.begin();
	for(; it != end && rit != rules_contents.end(); it++, rit++)
	{
		rc.emplace(*it, *rit);
	}

	// Both it and rit must be at the end, otherwise
	// there's a bug in the above
	if(it != end || rit != rules_contents.end())
	{
		throw falco_exception("Unexpected mismatch in rules content name/rules content sets?");
	}

	return res;
}


}; // namespace actions
}; // namespace app
}; // namespace falco
