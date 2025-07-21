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

#include <falco/app/actions/helpers.h>
#include <falco/configuration.h>
#include <gtest/gtest.h>

TEST(Capture, generate_scap_file_path_realistic_scenario) {
	// Simulate a realistic timestamp (nanoseconds since epoch)
	uint64_t timestamp = 1648178040000000000ULL;  // 2022-03-25 04:14:00 CET (03:14:00 UTC) in ns,
	                                              // birth date of my son Michelangelo :)
	uint64_t evt_num = 1011;
	std::string prefix = "/var/log/falco/captures/security_event";

	std::string result = falco::app::actions::generate_scap_file_path(prefix, timestamp, evt_num);

	std::string expected =
	        "/var/log/falco/captures/security_event_01648178040000000000_00000000000000001011.scap";
	EXPECT_EQ(result, expected);
}

TEST(Capture, generate_scap_file_path_lexicographic_ordering) {
	std::string prefix = "/tmp/test";

	// Generate multiple file paths with different timestamps
	std::string path1 = falco::app::actions::generate_scap_file_path(prefix, 1000, 1);
	std::string path2 = falco::app::actions::generate_scap_file_path(prefix, 2000, 1);
	std::string path3 = falco::app::actions::generate_scap_file_path(prefix, 10000, 1);

	// Verify lexicographic ordering (important for file sorting)
	EXPECT_LT(path1, path2);
	EXPECT_LT(path2, path3);

	// Also test with same timestamp but different event numbers
	std::string path4 = falco::app::actions::generate_scap_file_path(prefix, 1000, 1);
	std::string path5 = falco::app::actions::generate_scap_file_path(prefix, 1000, 2);
	std::string path6 = falco::app::actions::generate_scap_file_path(prefix, 1000, 100);

	EXPECT_LT(path4, path5);
	EXPECT_LT(path5, path6);
}

TEST(Capture, generate_scap_file_path_empty_prefix) {
	std::string prefix = "";
	uint64_t timestamp = 123;
	uint64_t evt_num = 456;

	std::string result = falco::app::actions::generate_scap_file_path(prefix, timestamp, evt_num);

	std::string expected = "_00000000000000000123_00000000000000000456.scap";
	EXPECT_EQ(result, expected);
}

TEST(Capture, capture_config_disabled_by_default) {
	std::string config_content = R"(
plugins:
)";

	falco_configuration config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = config.init_from_content(config_content, {}));

	// Capture should be disabled by default
	EXPECT_FALSE(config.m_capture_enabled);
	EXPECT_EQ(config.m_capture_path_prefix, "/tmp/falco");
	EXPECT_EQ(config.m_capture_mode, capture_mode_t::RULES);
	EXPECT_EQ(config.m_capture_default_duration_ns, 5000 * 1000000LL);  // 5 seconds in ns
}

TEST(Capture, capture_config_enabled_rules_mode) {
	std::string config_content = R"(
capture:
  enabled: true
  path_prefix: /var/log/captures/falco
  mode: rules
  default_duration: 10000
)";

	falco_configuration config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = config.init_from_content(config_content, {}));

	EXPECT_TRUE(config.m_capture_enabled);
	EXPECT_EQ(config.m_capture_path_prefix, "/var/log/captures/falco");
	EXPECT_EQ(config.m_capture_mode, capture_mode_t::RULES);
	EXPECT_EQ(config.m_capture_default_duration_ns, 10000 * 1000000LL);  // 10 seconds in ns
}

TEST(Capture, capture_config_enabled_all_rules_mode) {
	std::string config_content = R"(
capture:
  enabled: true
  path_prefix: /tmp/debug/falco
  mode: all_rules
  default_duration: 30000
)";

	falco_configuration config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = config.init_from_content(config_content, {}));

	EXPECT_TRUE(config.m_capture_enabled);
	EXPECT_EQ(config.m_capture_path_prefix, "/tmp/debug/falco");
	EXPECT_EQ(config.m_capture_mode, capture_mode_t::ALL_RULES);
	EXPECT_EQ(config.m_capture_default_duration_ns, 30000 * 1000000LL);  // 30 seconds in ns
}

TEST(Capture, capture_config_invalid_mode) {
	std::string config_content = R"(
capture:
  enabled: true
  mode: invalid_mode
)";

	falco_configuration config;
	config_loaded_res res;

	// Should throw an exception for invalid mode
	EXPECT_THROW(res = config.init_from_content(config_content, {}), std::logic_error);
}
