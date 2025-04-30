// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <gtest/gtest.h>

#include "../test_falco_engine.h"

TEST_F(test_falco_engine, extra_format_all) {
	std::string rules_content = R"END(
- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
)END";

	m_engine->add_extra_output_format("evt.type=%evt.type", "", {}, "");
	ASSERT_TRUE(load_rules(rules_content, "legit_rules.yaml")) << m_load_result_string;

	EXPECT_EQ(get_compiled_rule_output("legit_rule"),
	          "user=%user.name command=%proc.cmdline file=%fd.name evt.type=%evt.type");
}

TEST_F(test_falco_engine, extra_format_by_rule) {
	std::string rules_content = R"END(
- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open
  output: out 1
  priority: INFO

- rule: another_rule
  desc: legit rule description
  condition: evt.type=open
  output: out 2
  priority: INFO
)END";

	m_engine->add_extra_output_format("evt.type=%evt.type", "", {}, "legit_rule");
	ASSERT_TRUE(load_rules(rules_content, "legit_rules.yaml")) << m_load_result_string;

	EXPECT_EQ(get_compiled_rule_output("legit_rule"), "out 1 evt.type=%evt.type");
	EXPECT_EQ(get_compiled_rule_output("another_rule"), "out 2");
}

TEST_F(test_falco_engine, extra_format_by_tag_rule) {
	std::string rules_content = R"END(
- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open
  output: out 1
  priority: INFO
  tags: [tag1]

- rule: another_rule
  desc: legit rule description
  condition: evt.type=open
  output: out 2
  priority: INFO
  tags: [tag1]

- rule: a_third_rule
  desc: legit rule description
  condition: evt.type=open
  output: out 3
  priority: INFO
  tags: [tag1, tag2]
)END";

	m_engine->add_extra_output_format("extra 1", "", {"tag1"}, "");
	m_engine->add_extra_output_format("extra 2", "", {}, "another_rule");
	m_engine->add_extra_output_format("extra 3", "", {"tag1", "tag2"}, "");

	ASSERT_TRUE(load_rules(rules_content, "legit_rules.yaml")) << m_load_result_string;

	EXPECT_EQ(get_compiled_rule_output("legit_rule"), "out 1 extra 1");
	EXPECT_EQ(get_compiled_rule_output("another_rule"), "out 2 extra 1 extra 2");
	EXPECT_EQ(get_compiled_rule_output("a_third_rule"), "out 3 extra 1 extra 3");
}

TEST_F(test_falco_engine, extra_format_empty_container_info) {
	std::string rules_content = R"END(
- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open
  output: out 1 (%container.info)
  priority: INFO
  tags: [tag1]
)END";

	ASSERT_TRUE(load_rules(rules_content, "legit_rules.yaml")) << m_load_result_string;

	auto output = get_compiled_rule_output("legit_rule");
	EXPECT_TRUE(output.find("%container.info") == output.npos);
}

TEST_F(test_falco_engine, extra_fields_all) {
	std::string rules_content = R"END(
- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
)END";

	std::unordered_map<std::string, std::string> extra_formatted_fields = {
	        {"my_field", "hello %evt.num"}};
	for(auto const& f : extra_formatted_fields) {
		m_engine->add_extra_output_formatted_field(f.first, f.second, "", {}, "");
	}

	ASSERT_TRUE(load_rules(rules_content, "legit_rules.yaml")) << m_load_result_string;

	EXPECT_EQ(get_compiled_rule_formatted_fields("legit_rule"), extra_formatted_fields);
}
