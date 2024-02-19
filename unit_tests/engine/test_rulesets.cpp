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

#include <gtest/gtest.h>
#include <engine/evttype_index_ruleset.h>

#define RULESET_0 0
#define RULESET_1 1
#define RULESET_2 2

/* Helpers methods */
static std::shared_ptr<sinsp_filter_factory> create_factory(sinsp* inspector, filter_check_list& list)
{
	return std::make_shared<sinsp_filter_factory>(inspector, list);
}

static std::shared_ptr<filter_ruleset> create_ruleset(std::shared_ptr<sinsp_filter_factory> f)
{
	return std::make_shared<evttype_index_ruleset>(f);
}

static std::shared_ptr<libsinsp::filter::ast::expr> create_ast(std::shared_ptr<sinsp_filter_factory> f)
{
	libsinsp::filter::parser parser("evt.type=open");
	return parser.parse();
}

static std::shared_ptr<sinsp_filter> create_filter(
	std::shared_ptr<sinsp_filter_factory> f,
	libsinsp::filter::ast::expr* ast)
{
	sinsp_filter_compiler compiler(f, ast);
	return std::shared_ptr<sinsp_filter>(compiler.compile());
}

TEST(Ruleset, enable_disable_rules_using_names)
{
	sinsp inspector;

	sinsp_filter_check_list filterlist;
	auto f = create_factory(&inspector, filterlist);
	auto r = create_ruleset(f);
	auto ast = create_ast(f);
	auto filter = create_filter(f, ast.get());

	falco_rule rule_A = {};
	rule_A.name = "rule_A";
	rule_A.source = falco_common::syscall_source;

	falco_rule rule_B = {};
	rule_B.name = "rule_B";
	rule_B.source = falco_common::syscall_source;

	falco_rule rule_C = {};
	rule_C.name = "rule_C";
	rule_C.source = falco_common::syscall_source;

	r->add(rule_A, filter, ast);
	r->add(rule_B, filter, ast);
	r->add(rule_C, filter, ast);

	/* Enable `rule_A` for RULESET_0 */
	r->enable(rule_A.name, true, RULESET_0);
	ASSERT_EQ(r->enabled_count(RULESET_0), 1);
	ASSERT_EQ(r->enabled_count(RULESET_1), 0);
	ASSERT_EQ(r->enabled_count(RULESET_2), 0);

	/* Disable `rule_A` for RULESET_1, this should have no effect */
	r->disable(rule_A.name, true, RULESET_1);
	ASSERT_EQ(r->enabled_count(RULESET_0), 1);
	ASSERT_EQ(r->enabled_count(RULESET_1), 0);
	ASSERT_EQ(r->enabled_count(RULESET_2), 0);

	/* Enable a not existing rule for RULESET_2, this should have no effect */
	r->disable("<NA>", true, RULESET_2);
	ASSERT_EQ(r->enabled_count(RULESET_0), 1);
	ASSERT_EQ(r->enabled_count(RULESET_1), 0);
	ASSERT_EQ(r->enabled_count(RULESET_2), 0);

	/* Enable all rules for RULESET_0 */
	r->enable("rule_", false, RULESET_0);
	ASSERT_EQ(r->enabled_count(RULESET_0), 3);
	ASSERT_EQ(r->enabled_count(RULESET_1), 0);
	ASSERT_EQ(r->enabled_count(RULESET_2), 0);

	/* Try to disable all rules with exact match for RULESET_0, this should have no effect */
	r->disable("rule_", true, RULESET_0);
	ASSERT_EQ(r->enabled_count(RULESET_0), 3);
	ASSERT_EQ(r->enabled_count(RULESET_1), 0);
	ASSERT_EQ(r->enabled_count(RULESET_2), 0);

	/* Disable all rules for RULESET_0 */
	r->disable("rule_", false, RULESET_0);
	ASSERT_EQ(r->enabled_count(RULESET_0), 0);
	ASSERT_EQ(r->enabled_count(RULESET_1), 0);
	ASSERT_EQ(r->enabled_count(RULESET_2), 0);

	/* Enable rule_C for RULESET_2 without exact_match */
	r->enable("_C", false, RULESET_2);
	ASSERT_EQ(r->enabled_count(RULESET_0), 0);
	ASSERT_EQ(r->enabled_count(RULESET_1), 0);
	ASSERT_EQ(r->enabled_count(RULESET_2), 1);
}

TEST(Ruleset, enable_disable_rules_using_tags)
{
	sinsp inspector;

	sinsp_filter_check_list filterlist;
	auto f = create_factory(&inspector, filterlist);
	auto r = create_ruleset(f);
	auto ast = create_ast(f);
	auto filter = create_filter(f, ast.get());

	falco_rule rule_A = {};
	rule_A.name = "rule_A";
	rule_A.source = falco_common::syscall_source;
	rule_A.tags = {"first_rule_A_tag", "second_rule_A_tag", "common_tag"};

	falco_rule rule_B = {};
	rule_B.name = "rule_B";
	rule_B.source = falco_common::syscall_source;
	rule_B.tags = {"first_rule_B_tag", "second_rule_B_tag", "common_tag"};

	r->add(rule_A, filter, ast);
	r->add(rule_B, filter, ast);

	/* Enable `rule_A` for RULESET_0 using its first tag */
	r->enable_tags({"first_rule_A_tag"}, RULESET_0);
	ASSERT_EQ(r->enabled_count(RULESET_0), 1);
	ASSERT_EQ(r->enabled_count(RULESET_1), 0);
	ASSERT_EQ(r->enabled_count(RULESET_2), 0);

	/* Disable `rule_A` for RULESET_1 using its first tag, this should have no effect */
	r->disable_tags({"first_rule_A_tag"}, RULESET_1);
	ASSERT_EQ(r->enabled_count(RULESET_0), 1);
	ASSERT_EQ(r->enabled_count(RULESET_1), 0);
	ASSERT_EQ(r->enabled_count(RULESET_2), 0);

	/* Enable a not existing rule for RULESET_0, this should have no effect */
	r->enable_tags({"<NA_tag>"}, RULESET_0);
	ASSERT_EQ(r->enabled_count(RULESET_0), 1);
	ASSERT_EQ(r->enabled_count(RULESET_1), 0);
	ASSERT_EQ(r->enabled_count(RULESET_2), 0);

	/* Enable all rules for RULESET_2 */
	r->enable_tags({"common_tag"}, RULESET_2);
	ASSERT_EQ(r->enabled_count(RULESET_0), 1);
	ASSERT_EQ(r->enabled_count(RULESET_1), 0);
	ASSERT_EQ(r->enabled_count(RULESET_2), 2);

	/* Disable `rule_A` for RULESET_0 using its second tag
	 * Note that we have previously enabled it using the first tag,
	 * so here we are using a different tag of the rule t disable it!
	 */
	r->disable_tags({"second_rule_A_tag"}, RULESET_0);
	ASSERT_EQ(r->enabled_count(RULESET_0), 0);
	ASSERT_EQ(r->enabled_count(RULESET_1), 0);
	ASSERT_EQ(r->enabled_count(RULESET_2), 2);

	/* Disable all rules for RULESET_2 */
	r->disable_tags({"common_tag"}, RULESET_2);
	ASSERT_EQ(r->enabled_count(RULESET_0), 0);
	ASSERT_EQ(r->enabled_count(RULESET_1), 0);
	ASSERT_EQ(r->enabled_count(RULESET_2), 0);
}
