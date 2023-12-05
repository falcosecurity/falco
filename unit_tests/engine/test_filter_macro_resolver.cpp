// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless ASSERT_EQd by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <gtest/gtest.h>
#include <engine/filter_macro_resolver.h>

static std::vector<filter_macro_resolver::value_info>::const_iterator find_value(
	const std::vector<filter_macro_resolver::value_info>& values,
	const std::string& ref)
{
	return std::find_if(
		values.begin(),
		values.end(),
		[&ref](const filter_macro_resolver::value_info& v)
		{ return v.first == ref; });
}

#define MACRO_NAME "test_macro"
#define MACRO_A_NAME "test_macro_1"
#define MACRO_B_NAME "test_macro_2"

TEST(MacroResolver, should_resolve_macros_on_a_filter_AST)
{
	libsinsp::filter::ast::pos_info macro_pos(12, 85, 27);

	std::shared_ptr<libsinsp::filter::ast::expr> macro = libsinsp::filter::ast::unary_check_expr::create("test.field", "", "exists");

	std::vector<std::unique_ptr<libsinsp::filter::ast::expr>> filter_and;
	filter_and.push_back(libsinsp::filter::ast::unary_check_expr::create("evt.name", "", "exists"));
	filter_and.push_back(libsinsp::filter::ast::not_expr::create(libsinsp::filter::ast::value_expr::create(MACRO_NAME, macro_pos)));
	std::shared_ptr<libsinsp::filter::ast::expr> filter = libsinsp::filter::ast::and_expr::create(filter_and);

	std::vector<std::unique_ptr<libsinsp::filter::ast::expr>> expected_and;
	expected_and.push_back(libsinsp::filter::ast::unary_check_expr::create("evt.name", "", "exists"));
	expected_and.push_back(libsinsp::filter::ast::not_expr::create(clone(macro.get())));
	std::shared_ptr<libsinsp::filter::ast::expr> expected = libsinsp::filter::ast::and_expr::create(expected_and);

	filter_macro_resolver resolver;
	resolver.set_macro(MACRO_NAME, macro);

	// first run
	ASSERT_TRUE(resolver.run(filter));
	ASSERT_EQ(resolver.get_resolved_macros().size(), 1);
	ASSERT_STREQ(resolver.get_resolved_macros().begin()->first.c_str(), MACRO_NAME);
	ASSERT_EQ(resolver.get_resolved_macros().begin()->second, macro_pos);
	ASSERT_TRUE(resolver.get_unknown_macros().empty());
	ASSERT_TRUE(filter->is_equal(expected.get()));

	// second run
	ASSERT_FALSE(resolver.run(filter));
	ASSERT_TRUE(resolver.get_resolved_macros().empty());
	ASSERT_TRUE(resolver.get_unknown_macros().empty());
	ASSERT_TRUE(filter->is_equal(expected.get()));
}

TEST(MacroResolver, should_resolve_macros_on_a_filter_AST_single_node)
{
	libsinsp::filter::ast::pos_info macro_pos(12, 85, 27);

	std::shared_ptr<libsinsp::filter::ast::expr> macro = libsinsp::filter::ast::unary_check_expr::create("test.field", "", "exists");

	std::shared_ptr<libsinsp::filter::ast::expr> filter = libsinsp::filter::ast::value_expr::create(MACRO_NAME, macro_pos);

	filter_macro_resolver resolver;
	resolver.set_macro(MACRO_NAME, macro);

	// first run
	libsinsp::filter::ast::expr* old_filter_ptr = filter.get();
	ASSERT_TRUE(resolver.run(filter));
	ASSERT_NE(filter.get(), old_filter_ptr);
	ASSERT_EQ(resolver.get_resolved_macros().size(), 1);
	ASSERT_STREQ(resolver.get_resolved_macros().begin()->first.c_str(), MACRO_NAME);
	ASSERT_EQ(resolver.get_resolved_macros().begin()->second, macro_pos);
	ASSERT_TRUE(resolver.get_unknown_macros().empty());
	ASSERT_TRUE(filter->is_equal(macro.get()));

	// second run
	old_filter_ptr = filter.get();
	ASSERT_FALSE(resolver.run(filter));
	ASSERT_EQ(filter.get(), old_filter_ptr);
	ASSERT_TRUE(resolver.get_resolved_macros().empty());
	ASSERT_TRUE(resolver.get_unknown_macros().empty());
	ASSERT_TRUE(filter->is_equal(macro.get()));
}

TEST(MacroResolver, should_resolve_macros_on_a_filter_AST_multiple_macros)
{
	libsinsp::filter::ast::pos_info a_macro_pos(11, 75, 43);
	libsinsp::filter::ast::pos_info b_macro_pos(91, 21, 9);

	std::shared_ptr<libsinsp::filter::ast::expr> a_macro = libsinsp::filter::ast::unary_check_expr::create("one.field", "", "exists");
	std::shared_ptr<libsinsp::filter::ast::expr> b_macro = libsinsp::filter::ast::unary_check_expr::create("another.field", "", "exists");

	std::vector<std::unique_ptr<libsinsp::filter::ast::expr>> filter_or;
	filter_or.push_back(libsinsp::filter::ast::value_expr::create(MACRO_A_NAME, a_macro_pos));
	filter_or.push_back(libsinsp::filter::ast::value_expr::create(MACRO_B_NAME, b_macro_pos));
	std::shared_ptr<libsinsp::filter::ast::expr> filter = libsinsp::filter::ast::or_expr::create(filter_or);

	std::vector<std::unique_ptr<libsinsp::filter::ast::expr>> expected_or;
	expected_or.push_back(clone(a_macro.get()));
	expected_or.push_back(clone(b_macro.get()));
	std::shared_ptr<libsinsp::filter::ast::expr> expected_filter = libsinsp::filter::ast::or_expr::create(expected_or);

	filter_macro_resolver resolver;
	resolver.set_macro(MACRO_A_NAME, a_macro);
	resolver.set_macro(MACRO_B_NAME, b_macro);

	// first run
	ASSERT_TRUE(resolver.run(filter));
	ASSERT_EQ(resolver.get_resolved_macros().size(), 2);
	auto a_resolved_itr = find_value(resolver.get_resolved_macros(), MACRO_A_NAME);
	ASSERT_NE(a_resolved_itr, resolver.get_resolved_macros().end());
	ASSERT_STREQ(a_resolved_itr->first.c_str(), MACRO_A_NAME);
	ASSERT_EQ(a_resolved_itr->second, a_macro_pos);

	auto b_resolved_itr = find_value(resolver.get_resolved_macros(), MACRO_B_NAME);
	ASSERT_NE(b_resolved_itr, resolver.get_resolved_macros().end());
	ASSERT_TRUE(resolver.get_unknown_macros().empty());
	ASSERT_STREQ(b_resolved_itr->first.c_str(), MACRO_B_NAME);
	ASSERT_EQ(b_resolved_itr->second, b_macro_pos);
	ASSERT_TRUE(filter->is_equal(expected_filter.get()));

	// second run
	ASSERT_FALSE(resolver.run(filter));
	ASSERT_TRUE(resolver.get_resolved_macros().empty());
	ASSERT_TRUE(resolver.get_unknown_macros().empty());
	ASSERT_TRUE(filter->is_equal(expected_filter.get()));
}

TEST(MacroResolver, should_resolve_macros_on_a_filter_AST_nested_macros)
{
	libsinsp::filter::ast::pos_info a_macro_pos(47, 1, 76);
	libsinsp::filter::ast::pos_info b_macro_pos(111, 65, 2);

	std::vector<std::unique_ptr<libsinsp::filter::ast::expr>> a_macro_and;
	a_macro_and.push_back(libsinsp::filter::ast::unary_check_expr::create("one.field", "", "exists"));
	a_macro_and.push_back(libsinsp::filter::ast::value_expr::create(MACRO_B_NAME, b_macro_pos));
	std::shared_ptr<libsinsp::filter::ast::expr> a_macro = libsinsp::filter::ast::and_expr::create(a_macro_and);

	std::shared_ptr<libsinsp::filter::ast::expr> b_macro =
		libsinsp::filter::ast::unary_check_expr::create("another.field", "", "exists");

	std::shared_ptr<libsinsp::filter::ast::expr> filter = libsinsp::filter::ast::value_expr::create(MACRO_A_NAME, a_macro_pos);

	std::vector<std::unique_ptr<libsinsp::filter::ast::expr>> expected_and;
	expected_and.push_back(libsinsp::filter::ast::unary_check_expr::create("one.field", "", "exists"));
	expected_and.push_back(libsinsp::filter::ast::unary_check_expr::create("another.field", "", "exists"));
	std::shared_ptr<libsinsp::filter::ast::expr> expected_filter = libsinsp::filter::ast::and_expr::create(expected_and);

	filter_macro_resolver resolver;
	resolver.set_macro(MACRO_A_NAME, a_macro);
	resolver.set_macro(MACRO_B_NAME, b_macro);

	// first run
	ASSERT_TRUE(resolver.run(filter));
	ASSERT_EQ(resolver.get_resolved_macros().size(), 2);
	auto a_resolved_itr = find_value(resolver.get_resolved_macros(), MACRO_A_NAME);
	ASSERT_NE(a_resolved_itr, resolver.get_resolved_macros().end());
	ASSERT_STREQ(a_resolved_itr->first.c_str(), MACRO_A_NAME);
	ASSERT_EQ(a_resolved_itr->second, a_macro_pos);

	auto b_resolved_itr = find_value(resolver.get_resolved_macros(), MACRO_B_NAME);
	ASSERT_NE(b_resolved_itr, resolver.get_resolved_macros().end());
	ASSERT_TRUE(resolver.get_unknown_macros().empty());
	ASSERT_STREQ(b_resolved_itr->first.c_str(), MACRO_B_NAME);
	ASSERT_EQ(b_resolved_itr->second, b_macro_pos);

	ASSERT_TRUE(resolver.get_unknown_macros().empty());
	ASSERT_TRUE(filter->is_equal(expected_filter.get()));

	// second run
	ASSERT_FALSE(resolver.run(filter));
	ASSERT_TRUE(resolver.get_resolved_macros().empty());
	ASSERT_TRUE(resolver.get_unknown_macros().empty());
	ASSERT_TRUE(filter->is_equal(expected_filter.get()));
}

TEST(MacroResolver, should_find_unknown_macros)
{
	libsinsp::filter::ast::pos_info macro_pos(9, 4, 2);

	std::vector<std::unique_ptr<libsinsp::filter::ast::expr>> filter_and;
	filter_and.push_back(libsinsp::filter::ast::unary_check_expr::create("evt.name", "", "exists"));
	filter_and.push_back(libsinsp::filter::ast::not_expr::create(libsinsp::filter::ast::value_expr::create(MACRO_NAME, macro_pos)));
	std::shared_ptr<libsinsp::filter::ast::expr> filter = libsinsp::filter::ast::and_expr::create(filter_and);

	filter_macro_resolver resolver;
	ASSERT_FALSE(resolver.run(filter));
	ASSERT_EQ(resolver.get_unknown_macros().size(), 1);
	ASSERT_STREQ(resolver.get_unknown_macros().begin()->first.c_str(), MACRO_NAME);
	ASSERT_EQ(resolver.get_unknown_macros().begin()->second, macro_pos);
	ASSERT_TRUE(resolver.get_resolved_macros().empty());
}

TEST(MacroResolver, should_find_unknown_nested_macros)
{
	libsinsp::filter::ast::pos_info a_macro_pos(32, 84, 9);
	libsinsp::filter::ast::pos_info b_macro_pos(1, 0, 5);

	std::vector<std::unique_ptr<libsinsp::filter::ast::expr>> a_macro_and;
	a_macro_and.push_back(libsinsp::filter::ast::unary_check_expr::create("one.field", "", "exists"));
	a_macro_and.push_back(libsinsp::filter::ast::value_expr::create(MACRO_B_NAME, b_macro_pos));
	std::shared_ptr<libsinsp::filter::ast::expr> a_macro = libsinsp::filter::ast::and_expr::create(a_macro_and);

	std::shared_ptr<libsinsp::filter::ast::expr> filter = libsinsp::filter::ast::value_expr::create(MACRO_A_NAME, a_macro_pos);
	auto expected_filter = clone(a_macro.get());

	filter_macro_resolver resolver;
	resolver.set_macro(MACRO_A_NAME, a_macro);

	ASSERT_TRUE(resolver.run(filter));
	ASSERT_EQ(resolver.get_resolved_macros().size(), 1);
	ASSERT_STREQ(resolver.get_resolved_macros().begin()->first.c_str(), MACRO_A_NAME);
	ASSERT_EQ(resolver.get_resolved_macros().begin()->second, a_macro_pos);
	ASSERT_EQ(resolver.get_unknown_macros().size(), 1);
	ASSERT_STREQ(resolver.get_unknown_macros().begin()->first.c_str(), MACRO_B_NAME);
	ASSERT_EQ(resolver.get_unknown_macros().begin()->second, b_macro_pos);
	ASSERT_TRUE(filter->is_equal(expected_filter.get()));
}

TEST(MacroResolver, should_undefine_macro)
{
	libsinsp::filter::ast::pos_info macro_pos_1(12, 9, 3);
	libsinsp::filter::ast::pos_info macro_pos_2(9, 6, 3);

	std::shared_ptr<libsinsp::filter::ast::expr> macro = libsinsp::filter::ast::unary_check_expr::create("test.field", "", "exists");
	std::shared_ptr<libsinsp::filter::ast::expr> a_filter = libsinsp::filter::ast::value_expr::create(MACRO_NAME, macro_pos_1);
	std::shared_ptr<libsinsp::filter::ast::expr> b_filter = libsinsp::filter::ast::value_expr::create(MACRO_NAME, macro_pos_2);
	filter_macro_resolver resolver;

	resolver.set_macro(MACRO_NAME, macro);
	ASSERT_TRUE(resolver.run(a_filter));
	ASSERT_EQ(resolver.get_resolved_macros().size(), 1);
	ASSERT_STREQ(resolver.get_resolved_macros().begin()->first.c_str(), MACRO_NAME);
	ASSERT_EQ(resolver.get_resolved_macros().begin()->second, macro_pos_1);
	ASSERT_TRUE(resolver.get_unknown_macros().empty());
	ASSERT_TRUE(a_filter->is_equal(macro.get()));

	resolver.set_macro(MACRO_NAME, NULL);
	ASSERT_FALSE(resolver.run(b_filter));
	ASSERT_TRUE(resolver.get_resolved_macros().empty());
	ASSERT_EQ(resolver.get_unknown_macros().size(), 1);
	ASSERT_STREQ(resolver.get_unknown_macros().begin()->first.c_str(), MACRO_NAME);
	ASSERT_EQ(resolver.get_unknown_macros().begin()->second, macro_pos_2);
}

/* checks that the macro AST is cloned and not shared across resolved filters */
TEST(MacroResolver, should_clone_macro_AST)
{
	libsinsp::filter::ast::pos_info macro_pos(5, 2, 8888);
	std::shared_ptr<libsinsp::filter::ast::unary_check_expr> macro = libsinsp::filter::ast::unary_check_expr::create("test.field", "", "exists");
	std::shared_ptr<libsinsp::filter::ast::expr> filter = libsinsp::filter::ast::value_expr::create(MACRO_NAME, macro_pos);
	filter_macro_resolver resolver;

	resolver.set_macro(MACRO_NAME, macro);
	ASSERT_TRUE(resolver.run(filter));
	ASSERT_EQ(resolver.get_resolved_macros().size(), 1);
	ASSERT_STREQ(resolver.get_resolved_macros().begin()->first.c_str(), MACRO_NAME);
	ASSERT_EQ(resolver.get_resolved_macros().begin()->second, macro_pos);
	ASSERT_TRUE(resolver.get_unknown_macros().empty());
	ASSERT_TRUE(filter->is_equal(macro.get()));

	macro->field = "another.field";
	ASSERT_FALSE(filter->is_equal(macro.get()));
}
