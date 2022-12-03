/*
Copyright (C) 2020 The Falco Authors.

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

#include "filter_macro_resolver.h"
#include <catch.hpp>

using namespace libsinsp::filter::ast;

static std::vector<filter_macro_resolver::value_info>::const_iterator find_value(
		const std::vector<filter_macro_resolver::value_info>& values,
		const std::string& ref)
{
	return std::find_if(
		values.begin(),
		values.end(),
		[&ref](const filter_macro_resolver::value_info& v) { return v.first == ref; });
}

TEST_CASE("Should resolve macros on a filter AST", "[rule_loader]")
{
	std::string macro_name = "test_macro";
	pos_info macro_pos(12, 85, 27);

	SECTION("in the general case")
	{
		std::shared_ptr<expr> macro = std::move(
			unary_check_expr::create("test.field", "", "exists"));

		std::vector<std::unique_ptr<expr>> filter_and;
		filter_and.push_back(unary_check_expr::create("evt.name", "", "exists"));
		filter_and.push_back(not_expr::create(value_expr::create(macro_name, macro_pos)));
		std::shared_ptr<expr> filter = std::move(and_expr::create(filter_and));

		std::vector<std::unique_ptr<expr>> expected_and;
		expected_and.push_back(unary_check_expr::create("evt.name", "", "exists"));
		expected_and.push_back(not_expr::create(clone(macro.get())));
		std::shared_ptr<expr> expected = std::move(and_expr::create(expected_and));

		filter_macro_resolver resolver;
		resolver.set_macro(macro_name, macro);

		// first run
		REQUIRE(resolver.run(filter) == true);
		REQUIRE(resolver.get_resolved_macros().size() == 1);
		REQUIRE(resolver.get_resolved_macros().begin()->first == macro_name);
		REQUIRE(resolver.get_resolved_macros().begin()->second == macro_pos);
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(expected.get()));

		// second run
		REQUIRE(resolver.run(filter) == false);
		REQUIRE(resolver.get_resolved_macros().empty());
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(expected.get()));
	}

	SECTION("with a single node")
	{
		std::shared_ptr<expr> macro = std::move(
			unary_check_expr::create("test.field", "", "exists"));

		std::shared_ptr<expr> filter = std::move(value_expr::create(macro_name, macro_pos));

		filter_macro_resolver resolver;
		resolver.set_macro(macro_name, macro);

		// first run
		expr* old_filter_ptr = filter.get();
		REQUIRE(resolver.run(filter) == true);
		REQUIRE(filter.get() != old_filter_ptr);
		REQUIRE(resolver.get_resolved_macros().size() == 1);
		REQUIRE(resolver.get_resolved_macros().begin()->first == macro_name);
		REQUIRE(resolver.get_resolved_macros().begin()->second == macro_pos);
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(macro.get()));

		// second run
		old_filter_ptr = filter.get();
		REQUIRE(resolver.run(filter) == false);
		REQUIRE(filter.get() == old_filter_ptr);
		REQUIRE(resolver.get_resolved_macros().empty());
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(macro.get()));
	}

	SECTION("with multiple macros")
	{
		std::string a_macro_name = macro_name + "_1";
		std::string b_macro_name = macro_name + "_2";

		pos_info a_macro_pos(11, 75, 43);
		pos_info b_macro_pos(91, 21, 9);

		std::shared_ptr<expr> a_macro = std::move(
			unary_check_expr::create("one.field", "", "exists"));
		std::shared_ptr<expr> b_macro = std::move(
			unary_check_expr::create("another.field", "", "exists"));

		std::vector<std::unique_ptr<expr>> filter_or;
		filter_or.push_back(value_expr::create(a_macro_name, a_macro_pos));
		filter_or.push_back(value_expr::create(b_macro_name, b_macro_pos));
		std::shared_ptr<expr> filter = std::move(or_expr::create(filter_or));

		std::vector<std::unique_ptr<expr>> expected_or;
		expected_or.push_back(clone(a_macro.get()));
		expected_or.push_back(clone(b_macro.get()));
		std::shared_ptr<expr>  expected_filter = std::move(or_expr::create(expected_or));

		filter_macro_resolver resolver;
		resolver.set_macro(a_macro_name, a_macro);
		resolver.set_macro(b_macro_name, b_macro);

		// first run
		REQUIRE(resolver.run(filter) == true);
		REQUIRE(resolver.get_resolved_macros().size() == 2);
		auto a_resolved_itr = find_value(resolver.get_resolved_macros(), a_macro_name);
		REQUIRE(a_resolved_itr != resolver.get_resolved_macros().end());
		REQUIRE(a_resolved_itr->first == a_macro_name);
		REQUIRE(a_resolved_itr->second == a_macro_pos);

		auto b_resolved_itr = find_value(resolver.get_resolved_macros(), b_macro_name);
		REQUIRE(b_resolved_itr != resolver.get_resolved_macros().end());
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(b_resolved_itr->first == b_macro_name);
		REQUIRE(b_resolved_itr->second == b_macro_pos);
		REQUIRE(filter->is_equal(expected_filter.get()));

		// second run
		REQUIRE(resolver.run(filter) == false);
		REQUIRE(resolver.get_resolved_macros().empty());
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(expected_filter.get()));
	}

	SECTION("with nested macros")
	{
		std::string a_macro_name = macro_name + "_1";
		std::string b_macro_name = macro_name + "_2";

		pos_info a_macro_pos(47, 1, 76);
		pos_info b_macro_pos(111, 65, 2);

		std::vector<std::unique_ptr<expr>> a_macro_and;
		a_macro_and.push_back(unary_check_expr::create("one.field", "", "exists"));
		a_macro_and.push_back(value_expr::create(b_macro_name, b_macro_pos));
		std::shared_ptr<expr> a_macro = std::move(and_expr::create(a_macro_and));

		std::shared_ptr<expr> b_macro = std::move(
			unary_check_expr::create("another.field", "", "exists"));

		std::shared_ptr<expr> filter = std::move(value_expr::create(a_macro_name, a_macro_pos));

		std::vector<std::unique_ptr<expr>> expected_and;
		expected_and.push_back(unary_check_expr::create("one.field", "", "exists"));
		expected_and.push_back(unary_check_expr::create("another.field", "", "exists"));
		std::shared_ptr<expr> expected_filter = std::move(and_expr::create(expected_and));

		filter_macro_resolver resolver;
		resolver.set_macro(a_macro_name, a_macro);
		resolver.set_macro(b_macro_name, b_macro);

		// first run
		REQUIRE(resolver.run(filter) == true);
		REQUIRE(resolver.get_resolved_macros().size() == 2);
		auto a_resolved_itr = find_value(resolver.get_resolved_macros(), a_macro_name);
		REQUIRE(a_resolved_itr != resolver.get_resolved_macros().end());
		REQUIRE(a_resolved_itr->first == a_macro_name);
		REQUIRE(a_resolved_itr->second == a_macro_pos);

		auto b_resolved_itr = find_value(resolver.get_resolved_macros(), b_macro_name);
		REQUIRE(b_resolved_itr != resolver.get_resolved_macros().end());
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(b_resolved_itr->first == b_macro_name);
		REQUIRE(b_resolved_itr->second == b_macro_pos);

		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(expected_filter.get()));

		// second run
		REQUIRE(resolver.run(filter) == false);
		REQUIRE(resolver.get_resolved_macros().empty());
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(expected_filter.get()));
	}
}

TEST_CASE("Should find unknown macros", "[rule_loader]")
{
	std::string macro_name = "test_macro";
	pos_info macro_pos(9, 4, 2);

	SECTION("in the general case")
	{
		std::vector<std::unique_ptr<expr>> filter_and;
		filter_and.push_back(unary_check_expr::create("evt.name", "", "exists"));
		filter_and.push_back(not_expr::create(value_expr::create(macro_name, macro_pos)));
		std::shared_ptr<expr> filter = std::move(and_expr::create(filter_and));

		filter_macro_resolver resolver;
		REQUIRE(resolver.run(filter) == false);
		REQUIRE(resolver.get_unknown_macros().size() == 1);
		REQUIRE(resolver.get_unknown_macros().begin()->first == macro_name);
		REQUIRE(resolver.get_unknown_macros().begin()->second == macro_pos);
		REQUIRE(resolver.get_resolved_macros().empty());
	}

	SECTION("with nested macros")
	{
		std::string a_macro_name = macro_name + "_1";
		std::string b_macro_name = macro_name + "_2";

		pos_info a_macro_pos(32, 84, 9);
		pos_info b_macro_pos(1, 0, 5);

		std::vector<std::unique_ptr<expr>> a_macro_and;
		a_macro_and.push_back(unary_check_expr::create("one.field", "", "exists"));
		a_macro_and.push_back(value_expr::create(b_macro_name, b_macro_pos));
		std::shared_ptr<expr> a_macro = std::move(and_expr::create(a_macro_and));

		std::shared_ptr<expr> filter = std::move(value_expr::create(a_macro_name, a_macro_pos));
		auto expected_filter = clone(a_macro.get());

		filter_macro_resolver resolver;
		resolver.set_macro(a_macro_name, a_macro);

		// first run
		REQUIRE(resolver.run(filter) == true);
		REQUIRE(resolver.get_resolved_macros().size() == 1);
		REQUIRE(resolver.get_resolved_macros().begin()->first == a_macro_name);
		REQUIRE(resolver.get_resolved_macros().begin()->second == a_macro_pos);
		REQUIRE(resolver.get_unknown_macros().size() == 1);
		REQUIRE(resolver.get_unknown_macros().begin()->first == b_macro_name);
		REQUIRE(resolver.get_unknown_macros().begin()->second == b_macro_pos);
		REQUIRE(filter->is_equal(expected_filter.get()));
	}
}

TEST_CASE("Should undefine macro", "[rule_loader]")
{
	std::string macro_name = "test_macro";
	pos_info macro_pos_1(12, 9, 3);
	pos_info macro_pos_2(9, 6, 3);

	std::shared_ptr<expr> macro = std::move(unary_check_expr::create("test.field", "", "exists"));
	std::shared_ptr<expr> a_filter = std::move(value_expr::create(macro_name, macro_pos_1));
	std::shared_ptr<expr> b_filter = std::move(value_expr::create(macro_name, macro_pos_2));
	filter_macro_resolver resolver;

	resolver.set_macro(macro_name, macro);
	REQUIRE(resolver.run(a_filter) == true);
	REQUIRE(resolver.get_resolved_macros().size() == 1);
	REQUIRE(resolver.get_resolved_macros().begin()->first == macro_name);
	REQUIRE(resolver.get_resolved_macros().begin()->second == macro_pos_1);
	REQUIRE(resolver.get_unknown_macros().empty());
	REQUIRE(a_filter->is_equal(macro.get()));

	resolver.set_macro(macro_name, NULL);
	REQUIRE(resolver.run(b_filter) == false);
	REQUIRE(resolver.get_resolved_macros().empty());
	REQUIRE(resolver.get_unknown_macros().size() == 1);
	REQUIRE(resolver.get_unknown_macros().begin()->first == macro_name);
	REQUIRE(resolver.get_unknown_macros().begin()->second == macro_pos_2);
}

// checks that the macro AST is cloned and not shared across resolved filters
TEST_CASE("Should clone macro AST", "[rule_loader]")
{
	std::string macro_name = "test_macro";
	pos_info macro_pos(5, 2, 8888);
	std::shared_ptr<unary_check_expr> macro = std::move(unary_check_expr::create("test.field", "", "exists"));
	std::shared_ptr<expr> filter = std::move(value_expr::create(macro_name, macro_pos));
	filter_macro_resolver resolver;

	resolver.set_macro(macro_name, macro);
	REQUIRE(resolver.run(filter) == true);
	REQUIRE(resolver.get_resolved_macros().size() == 1);
	REQUIRE(resolver.get_resolved_macros().begin()->first == macro_name);
	REQUIRE(resolver.get_resolved_macros().begin()->second == macro_pos);
	REQUIRE(resolver.get_unknown_macros().empty());
	REQUIRE(filter->is_equal(macro.get()));

	macro->field = "another.field";
	REQUIRE(!filter->is_equal(macro.get()));
}
