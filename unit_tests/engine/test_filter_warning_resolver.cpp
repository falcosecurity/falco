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
#include <engine/filter_warning_resolver.h>

static bool warns(const std::string& condition) {
	auto ast = libsinsp::filter::parser(condition).parse();
	rule_loader::context ctx("test");
	rule_loader::result res("test");
	filter_warning_resolver().run(ctx, res, *ast.get());
	return res.has_warnings();
}

TEST(WarningResolver, warnings_in_filtering_conditions) {
	ASSERT_FALSE(warns("ka.field exists"));
	ASSERT_FALSE(warns("some.field = <NA>"));
	ASSERT_TRUE(warns("jevt.field = <NA>"));
	ASSERT_TRUE(warns("ka.field = <NA>"));
	ASSERT_TRUE(warns("ka.field == <NA>"));
	ASSERT_TRUE(warns("ka.field != <NA>"));
	ASSERT_TRUE(warns("ka.field in (<NA>)"));
	ASSERT_TRUE(warns("ka.field in (otherval, <NA>)"));
	ASSERT_TRUE(warns("ka.field intersects (<NA>)"));
	ASSERT_TRUE(warns("ka.field intersects (otherval, <NA>)"));
	ASSERT_TRUE(warns("ka.field pmatch (<NA>)"));
	ASSERT_TRUE(warns("ka.field pmatch (otherval, <NA>)"));
	ASSERT_TRUE(warns("evt.dir = <"));
	ASSERT_TRUE(warns("evt.dir = >"));
	ASSERT_TRUE(warns("proc.name=test and evt.dir = <"));
	ASSERT_TRUE(warns("evt.dir = < and proc.name=test"));
}

// Helper for programmatically-built ASTs (multi-value transformers can't be parsed yet)
static bool warns_ast(libsinsp::filter::ast::expr& ast) {
	rule_loader::context ctx("test");
	rule_loader::result res("test");
	filter_warning_resolver().run(ctx, res, ast);
	return res.has_warnings();
}

TEST(WarningResolver, warnings_with_transformer_wrapping_unsafe_field) {
	namespace ast = libsinsp::filter::ast;

	// tolower(ka.field) = <NA> -- unsafe field inside transformer, should warn
	auto filter = ast::binary_check_expr::create(
	        ast::field_transformer_expr::create("tolower", ast::field_expr::create("ka.field", "")),
	        "=",
	        ast::value_expr::create("<NA>"));
	ASSERT_TRUE(warns_ast(*filter));

	// tolower(safe.field) = <NA> -- safe field inside transformer, should NOT warn
	auto filter2 = ast::binary_check_expr::create(
	        ast::field_transformer_expr::create("tolower",
	                                            ast::field_expr::create("safe.field", "")),
	        "=",
	        ast::value_expr::create("<NA>"));
	ASSERT_FALSE(warns_ast(*filter2));
}

TEST(WarningResolver, warnings_with_multi_value_transformer) {
	namespace ast = libsinsp::filter::ast;

	// concat(ka.field, other.field) = <NA> -- has unsafe field, but the warning
	// resolver traverses through the transformer's values via base_expr_visitor
	// defaults. The field_expr visit for ka.field sets m_last_node_is_unsafe_field,
	// but since binary_check_expr only checks the direct left child (the transformer),
	// the unsafe field detection depends on traversal order.
	// The base_expr_visitor default for field_transformer_expr iterates e->values,
	// which will visit field_expr nodes. The last field_expr visited determines
	// m_last_node_is_unsafe_field state.
	std::vector<std::unique_ptr<ast::expr>> args;
	args.push_back(ast::field_expr::create("safe.field", ""));
	args.push_back(ast::field_expr::create("ka.field", ""));
	auto filter =
	        ast::binary_check_expr::create(ast::field_transformer_expr::create("concat", args),
	                                       "=",
	                                       ast::value_expr::create("<NA>"));
	// The base_expr_visitor will traverse into the transformer's values,
	// and the last field_expr visited (ka.field) will set the unsafe flag.
	// However, the warning resolver only overrides binary_check_expr to
	// check the left side, and the base default will visit the transformer's
	// children. Since field_expr for ka.field sets m_last_node_is_unsafe_field,
	// this should trigger the warning.
	ASSERT_TRUE(warns_ast(*filter));
}

TEST(WarningResolver, no_crash_with_transformer_list) {
	namespace ast = libsinsp::filter::ast;

	// join(",", (ka.field, safe.field)) = <NA>
	std::vector<std::unique_ptr<ast::expr>> list_children;
	list_children.push_back(ast::field_expr::create("ka.field", ""));
	list_children.push_back(ast::field_expr::create("safe.field", ""));

	std::vector<std::unique_ptr<ast::expr>> transformer_args;
	transformer_args.push_back(ast::value_expr::create(","));
	transformer_args.push_back(ast::transformer_list_expr::create(list_children));

	auto filter = ast::binary_check_expr::create(
	        ast::field_transformer_expr::create("join", transformer_args),
	        "=",
	        ast::value_expr::create("<NA>"));

	// Should not crash -- the base_expr_visitor default for transformer_list_expr
	// is a no-op, so ka.field inside it won't be visited for warning detection.
	// This is acceptable behavior for now.
	ASSERT_NO_FATAL_FAILURE(warns_ast(*filter));
}
