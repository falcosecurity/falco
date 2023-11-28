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

#include <string>

#include <gtest/gtest.h>

#include <sinsp.h>
#include <filter_check_list.h>
#include <filter.h>

#include <falco_engine.h>

static std::string single_rule = R"END(
- rule: test rule
  desc: A test rule
  condition: evt.type=execve
  output: A test rule matched (evt.type=%evt.type)
  priority: INFO
  source: syscall
  tags: [process]

- rule: disabled rule
  desc: A disabled rule
  condition: evt.type=execve
  output: A disabled rule matched (evt.type=%evt.type)
  priority: INFO
  source: syscall
  enabled: false
  tags: [exec process]
)END";

// This must be kept in line with the (private) falco_engine::s_default_ruleset
static const std::string default_ruleset = "falco-default-ruleset";

static const std::string ruleset_1 = "ruleset-1";
static const std::string ruleset_2 = "ruleset-2";
static const std::string ruleset_3 = "ruleset-3";
static const std::string ruleset_4 = "ruleset-4";

static void load_rules(falco_engine& engine, sinsp& inspector, sinsp_filter_check_list& filterchecks)
{
	std::unique_ptr<falco::load_result> res;

	auto filter_factory = std::shared_ptr<gen_event_filter_factory>(
		new sinsp_filter_factory(&inspector, filterchecks));
	auto formatter_factory = std::shared_ptr<gen_event_formatter_factory>(
		new sinsp_evt_formatter_factory(&inspector, filterchecks));

	engine.add_source("syscall", filter_factory, formatter_factory);

	res = engine.load_rules(single_rule, "single_rule.yaml");

	EXPECT_TRUE(res->successful());
}

TEST(EnableRule, enable_rule_name)
{
	falco_engine engine;
	sinsp inspector;
	sinsp_filter_check_list filterchecks;

	load_rules(engine, inspector, filterchecks);

	// No rules should be enabled yet for any custom rulesets
	EXPECT_EQ(1, engine.num_rules_for_ruleset(default_ruleset));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_3));

	// Enable for first ruleset, only that ruleset should have an
	// enabled rule afterward
	engine.enable_rule("test", true, ruleset_1);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_3));

	// Enable for second ruleset
	engine.enable_rule("test", true, ruleset_2);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_3));

	// When the substring is blank, all rules are enabled
	// (including the disabled rule)
	engine.enable_rule("", true, ruleset_3);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(2, engine.num_rules_for_ruleset(ruleset_3));

	// Now disable for second ruleset
	engine.enable_rule("test", false, ruleset_2);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(2, engine.num_rules_for_ruleset(ruleset_3));
}

TEST(EnableRule, enable_rule_tags)
{
	falco_engine engine;
	sinsp inspector;
	sinsp_filter_check_list filterchecks;
	std::set<std::string> process_tags = {"process"};

	load_rules(engine, inspector, filterchecks);

	// No rules should be enabled yet for any custom rulesets
	EXPECT_EQ(1, engine.num_rules_for_ruleset(default_ruleset));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_2));

	// Enable for first ruleset, only that ruleset should have an
	// enabled rule afterward
	engine.enable_rule_by_tag(process_tags, true, ruleset_1);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_2));

	// Enable for second ruleset
	engine.enable_rule_by_tag(process_tags, true, ruleset_2);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_2));

	// Now disable for second ruleset
	engine.enable_rule_by_tag(process_tags, false, ruleset_2);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_2));
}

TEST(EnableRule, enable_disabled_rule_by_tag)
{
	falco_engine engine;
	sinsp inspector;
	sinsp_filter_check_list filterchecks;
	std::set<std::string> exec_process_tags = {"exec process"};

	load_rules(engine, inspector, filterchecks);

	// Only the first rule should be enabled
	EXPECT_EQ(1, engine.num_rules_for_ruleset(default_ruleset));

	// Enable the disabled rule by tag
	engine.enable_rule_by_tag(exec_process_tags, true);

	// Both rules should be enabled now
	EXPECT_EQ(2, engine.num_rules_for_ruleset(default_ruleset));
}

TEST(EnableRule, enable_rule_id)
{
	falco_engine engine;
	sinsp inspector;
	sinsp_filter_check_list filterchecks;
	uint16_t ruleset_1_id;
	uint16_t ruleset_2_id;
	uint16_t ruleset_3_id;

	load_rules(engine, inspector, filterchecks);

	// The cases are identical to above, just using ruleset ids
	// instead of names.

	ruleset_1_id = engine.find_ruleset_id(ruleset_1);
	ruleset_2_id = engine.find_ruleset_id(ruleset_2);
	ruleset_3_id = engine.find_ruleset_id(ruleset_3);

	EXPECT_EQ(1, engine.num_rules_for_ruleset(default_ruleset));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_3));

	engine.enable_rule("test rule", true, ruleset_1_id);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_3));

	engine.enable_rule("test rule", true, ruleset_2_id);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_3));

	engine.enable_rule("", true, ruleset_3_id);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(2, engine.num_rules_for_ruleset(ruleset_3));

	engine.enable_rule("test", false, ruleset_2_id);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(2, engine.num_rules_for_ruleset(ruleset_3));
}

TEST(EnableRule, enable_rule_name_exact)
{
	falco_engine engine;
	sinsp inspector;
	sinsp_filter_check_list filterchecks;

	load_rules(engine, inspector, filterchecks);

	EXPECT_EQ(1, engine.num_rules_for_ruleset(default_ruleset));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_3));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_4));

	engine.enable_rule_exact("test rule", true, ruleset_1);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_3));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_4));

	engine.enable_rule_exact("test rule", true, ruleset_2);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_3));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_4));

	// This should **not** enable as this is a substring and not
	// an exact match.
	engine.enable_rule_exact("test", true, ruleset_3);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_3));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_4));

	engine.enable_rule_exact("", true, ruleset_4);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_3));
	EXPECT_EQ(2, engine.num_rules_for_ruleset(ruleset_4));

	engine.enable_rule("test rule", false, ruleset_2);
	EXPECT_EQ(1, engine.num_rules_for_ruleset(ruleset_1));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_2));
	EXPECT_EQ(0, engine.num_rules_for_ruleset(ruleset_3));
	EXPECT_EQ(2, engine.num_rules_for_ruleset(ruleset_4));
}
