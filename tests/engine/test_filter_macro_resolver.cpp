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

using namespace std;
using namespace libsinsp::filter::ast;

TEST_CASE("Should resolve macros on a filter AST", "[rule_loader]")
{
	string macro_name = "test_macro";

	SECTION("in the general case")
	{
		shared_ptr<expr> macro(
			new unary_check_expr("test.field", "", "exists"));

		expr* filter = new and_expr({
			new unary_check_expr("evt.name", "", "exists"), 
			new not_expr(
				new value_expr(macro_name)
			),
		});
		expr* expected_filter = new and_expr({
			new unary_check_expr("evt.name", "", "exists"), 
			new not_expr(clone(macro.get())),
		});

		filter_macro_resolver resolver;
		resolver.set_macro(macro_name, macro);

		// first run
		REQUIRE(resolver.run(filter) == true);
		REQUIRE(resolver.get_resolved_macros().size() == 1);
		REQUIRE(*resolver.get_resolved_macros().begin() == macro_name);
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(expected_filter));

		// second run
		REQUIRE(resolver.run(filter) == false);
		REQUIRE(resolver.get_resolved_macros().empty());
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(expected_filter));

		delete filter;
		delete expected_filter;
	}

	SECTION("with a single node")
	{
		shared_ptr<expr> macro(
			new unary_check_expr("test.field", "", "exists"));

		expr* filter = new value_expr(macro_name);

		filter_macro_resolver resolver;
		resolver.set_macro(macro_name, macro);

		// first run
		expr* old_filter_ptr = filter;
		REQUIRE(resolver.run(filter) == true);
		REQUIRE(filter != old_filter_ptr);
		REQUIRE(resolver.get_resolved_macros().size() == 1);
		REQUIRE(*resolver.get_resolved_macros().begin() == macro_name);
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(macro.get()));

		// second run
		old_filter_ptr = filter;
		REQUIRE(resolver.run(filter) == false);
		REQUIRE(filter == old_filter_ptr);
		REQUIRE(resolver.get_resolved_macros().empty());
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(macro.get()));

		delete filter;
	}

	SECTION("with multiple macros")
	{
		string a_macro_name = macro_name + "_1";
		string b_macro_name = macro_name + "_2";

		shared_ptr<expr> a_macro(
			new unary_check_expr("one.field", "", "exists"));
		shared_ptr<expr> b_macro(
			new unary_check_expr("another.field", "", "exists"));

		expr* filter = new or_expr({
			new value_expr(a_macro_name),
			new value_expr(b_macro_name),
		});
		expr* expected_filter = new or_expr({
			clone(a_macro.get()),
			clone(b_macro.get()),
		});

		filter_macro_resolver resolver;
		resolver.set_macro(a_macro_name, a_macro);
		resolver.set_macro(b_macro_name, b_macro);

		// first run
		REQUIRE(resolver.run(filter) == true);
		REQUIRE(resolver.get_resolved_macros().size() == 2);
		REQUIRE(resolver.get_resolved_macros().find(a_macro_name)
				!= resolver.get_resolved_macros().end());
		REQUIRE(resolver.get_resolved_macros().find(b_macro_name)
				!= resolver.get_resolved_macros().end());
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(expected_filter));

		// second run
		REQUIRE(resolver.run(filter) == false);
		REQUIRE(resolver.get_resolved_macros().empty());
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(expected_filter));

		delete filter;
		delete expected_filter;
	}

	SECTION("with nested macros")
	{
		string a_macro_name = macro_name + "_1";
		string b_macro_name = macro_name + "_2";

		shared_ptr<expr> a_macro(new and_expr({
			new unary_check_expr("one.field", "", "exists"),
			new value_expr(b_macro_name),
		}));
		shared_ptr<expr> b_macro(
			new unary_check_expr("another.field", "", "exists"));

		expr* filter = new value_expr(a_macro_name);
		expr* expected_filter = new and_expr({
			new unary_check_expr("one.field", "", "exists"),
			new unary_check_expr("another.field", "", "exists"),
		});

		filter_macro_resolver resolver;
		resolver.set_macro(a_macro_name, a_macro);
		resolver.set_macro(b_macro_name, b_macro);

		// first run
		REQUIRE(resolver.run(filter) == true);
		REQUIRE(resolver.get_resolved_macros().size() == 2);
		REQUIRE(resolver.get_resolved_macros().find(a_macro_name)
				!= resolver.get_resolved_macros().end());
		REQUIRE(resolver.get_resolved_macros().find(b_macro_name)
				!= resolver.get_resolved_macros().end());
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(expected_filter));

		// second run
		REQUIRE(resolver.run(filter) == false);
		REQUIRE(resolver.get_resolved_macros().empty());
		REQUIRE(resolver.get_unknown_macros().empty());
		REQUIRE(filter->is_equal(expected_filter));

		delete filter;
		delete expected_filter;
	}
}

TEST_CASE("Should find unknown macros", "[rule_loader]")
{
	string macro_name = "test_macro";

	SECTION("in the general case")
	{
		expr* filter = new and_expr({
			new unary_check_expr("evt.name", "", "exists"), 
			new not_expr(
				new value_expr(macro_name)
			),
		});

		filter_macro_resolver resolver;
		REQUIRE(resolver.run(filter) == false);
		REQUIRE(resolver.get_unknown_macros().size() == 1);
		REQUIRE(*resolver.get_unknown_macros().begin() == macro_name);
		REQUIRE(resolver.get_resolved_macros().empty());

		delete filter;
	}

	SECTION("with nested macros")
	{
		string a_macro_name = macro_name + "_1";
		string b_macro_name = macro_name + "_2";

		shared_ptr<expr> a_macro(new and_expr({
			new unary_check_expr("one.field", "", "exists"),
			new value_expr(b_macro_name),
		}));

		expr* filter = new value_expr(a_macro_name);
		expr* expected_filter = clone(a_macro.get());

		filter_macro_resolver resolver;
		resolver.set_macro(a_macro_name, a_macro);

		// first run
		REQUIRE(resolver.run(filter) == true);
		REQUIRE(resolver.get_resolved_macros().size() == 1);
		REQUIRE(*resolver.get_resolved_macros().begin() == a_macro_name);
		REQUIRE(resolver.get_unknown_macros().size() == 1);
		REQUIRE(*resolver.get_unknown_macros().begin() == b_macro_name);
		REQUIRE(filter->is_equal(expected_filter));

		delete filter;
		delete expected_filter;
	}
}

TEST_CASE("Should undefine macro", "[rule_loader]")
{
	string macro_name = "test_macro";
	shared_ptr<expr> macro(new unary_check_expr("test.field", "", "exists"));
	expr* a_filter = new value_expr(macro_name);
	expr* b_filter = new value_expr(macro_name);
	filter_macro_resolver resolver;

	resolver.set_macro(macro_name, macro);
	REQUIRE(resolver.run(a_filter) == true);
	REQUIRE(resolver.get_resolved_macros().size() == 1);
	REQUIRE(*resolver.get_resolved_macros().begin() == macro_name);
	REQUIRE(resolver.get_unknown_macros().empty());
	REQUIRE(a_filter->is_equal(macro.get()));

	resolver.set_macro(macro_name, NULL);
	REQUIRE(resolver.run(b_filter) == false);
	REQUIRE(resolver.get_resolved_macros().empty());
	REQUIRE(resolver.get_unknown_macros().size() == 1);
	REQUIRE(*resolver.get_unknown_macros().begin() == macro_name);

	delete a_filter;
	delete b_filter;
}

// checks that the macro AST is cloned and not shared across resolved filters
TEST_CASE("Should clone macro AST", "[rule_loader]")
{
	string macro_name = "test_macro";
	shared_ptr<unary_check_expr> macro(
		new unary_check_expr("test.field", "", "exists"));
	expr* filter = new value_expr(macro_name);
	filter_macro_resolver resolver;
	
	resolver.set_macro(macro_name, macro);
	REQUIRE(resolver.run(filter) == true);
	REQUIRE(resolver.get_resolved_macros().size() == 1);
	REQUIRE(*resolver.get_resolved_macros().begin() == macro_name);
	REQUIRE(resolver.get_unknown_macros().empty());
	REQUIRE(filter->is_equal(macro.get()));

	macro.get()->field = "another.field";
	REQUIRE(!filter->is_equal(macro.get()));

	delete filter;
}
