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
#include <falco/configuration.h>

TEST(ConfigurationRuleSelection, parse_yaml)
{
	falco_configuration falco_config;
	EXPECT_NO_THROW(falco_config.init_from_content(R"(
rules:
  - enable:
      rule: 'Terminal Shell in Container'

  - disable:
      tag: experimental

  - enable:
      rule: 'hello*'
	)", {}));

	ASSERT_EQ(falco_config.m_rules_selection.size(), 3);

	ASSERT_EQ(falco_config.m_rules_selection[0].m_op, falco_configuration::rule_selection_operation::enable);
	ASSERT_EQ(falco_config.m_rules_selection[0].m_rule, "Terminal Shell in Container");

	ASSERT_EQ(falco_config.m_rules_selection[1].m_op, falco_configuration::rule_selection_operation::disable);
	ASSERT_EQ(falco_config.m_rules_selection[1].m_tag, "experimental");

	ASSERT_EQ(falco_config.m_rules_selection[2].m_op, falco_configuration::rule_selection_operation::enable);
	ASSERT_EQ(falco_config.m_rules_selection[2].m_rule, "hello*");
}

TEST(ConfigurationRuleSelection, cli_options)
{
	falco_configuration falco_config;
	EXPECT_NO_THROW(falco_config.init_from_content("", std::vector<std::string>{"rules[].disable.tag=maturity_incubating", "rules[].enable.rule=Adding ssh keys to authorized_keys"}));

	ASSERT_EQ(falco_config.m_rules_selection.size(), 2);

	ASSERT_EQ(falco_config.m_rules_selection[0].m_op, falco_configuration::rule_selection_operation::disable);
	ASSERT_EQ(falco_config.m_rules_selection[0].m_tag, "maturity_incubating");

	ASSERT_EQ(falco_config.m_rules_selection[1].m_op, falco_configuration::rule_selection_operation::enable);
	ASSERT_EQ(falco_config.m_rules_selection[1].m_rule, "Adding ssh keys to authorized_keys");
}
