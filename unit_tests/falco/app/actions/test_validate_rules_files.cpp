// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include "app_action_helpers.h"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace {
const std::string s_hint =
        "--validate accepts Falco rules files only. To validate a Falco configuration file "
        "and its configured rules, use --dry-run.";

class stdout_capture {
public:
	stdout_capture(): m_original(std::cout.rdbuf(m_stream.rdbuf())) {}
	~stdout_capture() { std::cout.rdbuf(m_original); }

	std::string str() const { return m_stream.str(); }

private:
	std::ostringstream m_stream;
	std::streambuf* m_original;
};

falco::app::run_result validate_content(const std::string& filename,
                                        const std::string& content,
                                        bool json_output,
                                        std::string& output) {
	{
		std::ofstream file(filename);
		if(!file.is_open()) {
			return falco::app::run_result::fatal("Could not create test file " + filename);
		}
		file << content;
	}

	falco::app::state s = {};
	s.options.validate_rules_filenames = {filename};
	s.config->m_json_output = json_output;

	falco::app::run_result result;
	{
		stdout_capture capture;
		result = falco::app::actions::validate_rules_files(s);
		output = capture.str();
	}
	EXPECT_EQ(std::remove(filename.c_str()), 0);
	return result;
}
}  // namespace

TEST(ActionValidateRulesFiles, suggests_dry_run_for_config_file) {
	std::string output;
	auto result = validate_content("falco_config_for_rules_validation.yaml",
	                               "rules_files:\n  - /etc/falco/falco_rules.yaml\n",
	                               false,
	                               output);
	EXPECT_FALSE(result.success);
	EXPECT_FALSE(result.proceed);
	EXPECT_NE(result.errstr.find(s_hint), std::string::npos);
	EXPECT_NE(output.find(s_hint), std::string::npos);
}

TEST(ActionValidateRulesFiles, preserves_json_output_for_config_file) {
	std::string output;
	auto result = validate_content("falco_config_for_json_rules_validation.yaml",
	                               "rules_files:\n  - /etc/falco/falco_rules.yaml\n",
	                               true,
	                               output);
	auto json_output = nlohmann::json::parse(output, nullptr, false);
	EXPECT_FALSE(result.success);
	EXPECT_NE(result.errstr.find(s_hint), std::string::npos);
	EXPECT_TRUE(json_output.is_object());
	EXPECT_TRUE(json_output.contains("falco_load_results"));
	EXPECT_EQ(output.find(s_hint), std::string::npos);
}

TEST(ActionValidateRulesFiles, omits_config_hint_for_rules_sequence) {
	std::string output;
	auto result = validate_content("invalid_rules_for_validation.yaml",
	                               "- rule: missing required fields\n",
	                               false,
	                               output);
	EXPECT_FALSE(result.success);
	EXPECT_EQ(result.errstr.find(s_hint), std::string::npos);
	EXPECT_EQ(output.find(s_hint), std::string::npos);
}
