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
#include <engine/filter_details_resolver.h>

TEST(DetailsResolver, resolve_ast) {
	std::string cond =
	        "(spawned_process or evt.type = open) and (proc.name icontains cat or proc.name in "
	        "(known_procs, ps))";
	auto ast = libsinsp::filter::parser(cond).parse();
	filter_details details;
	details.known_macros.insert("spawned_process");
	details.known_lists.insert("known_procs");
	filter_details_resolver resolver;
	resolver.run(ast.get(), details);

	// Assert fields
	ASSERT_EQ(details.fields.size(), 2);
	ASSERT_NE(details.fields.find("evt.type"), details.fields.end());
	ASSERT_NE(details.fields.find("proc.name"), details.fields.end());

	// Assert macros
	ASSERT_EQ(details.macros.size(), 1);
	ASSERT_NE(details.macros.find("spawned_process"), details.macros.end());

	// Assert operators
	ASSERT_EQ(details.operators.size(), 3);
	ASSERT_NE(details.operators.find("="), details.operators.end());
	ASSERT_NE(details.operators.find("icontains"), details.operators.end());
	ASSERT_NE(details.operators.find("in"), details.operators.end());

	// Assert lists
	ASSERT_EQ(details.lists.size(), 1);
	ASSERT_NE(details.lists.find("known_procs"), details.lists.end());
}

// Tests for multi-value transformer support

TEST(DetailsResolver, resolve_single_value_transformer) {
	namespace ast = libsinsp::filter::ast;

	// Build: tolower(proc.name) = nginx
	auto filter = ast::binary_check_expr::create(
	        ast::field_transformer_expr::create("tolower",
	                                            ast::field_expr::create("proc.name", "")),
	        "=",
	        ast::value_expr::create("nginx"));

	filter_details details;
	filter_details_resolver resolver;
	resolver.run(filter.get(), details);

	ASSERT_EQ(details.fields.size(), 1);
	ASSERT_NE(details.fields.find("proc.name"), details.fields.end());
	ASSERT_EQ(details.transformers.size(), 1);
	ASSERT_NE(details.transformers.find("tolower"), details.transformers.end());
	ASSERT_EQ(details.operators.size(), 1);
	ASSERT_NE(details.operators.find("="), details.operators.end());
}

TEST(DetailsResolver, resolve_multi_value_transformer) {
	namespace ast = libsinsp::filter::ast;

	// Build: concat(proc.name, proc.pname) = value
	std::vector<std::unique_ptr<ast::expr>> args;
	args.push_back(ast::field_expr::create("proc.name", ""));
	args.push_back(ast::field_expr::create("proc.pname", ""));
	auto filter =
	        ast::binary_check_expr::create(ast::field_transformer_expr::create("concat", args),
	                                       "=",
	                                       ast::value_expr::create("value"));

	filter_details details;
	filter_details_resolver resolver;
	resolver.run(filter.get(), details);

	ASSERT_EQ(details.fields.size(), 2);
	ASSERT_NE(details.fields.find("proc.name"), details.fields.end());
	ASSERT_NE(details.fields.find("proc.pname"), details.fields.end());
	ASSERT_EQ(details.transformers.size(), 1);
	ASSERT_NE(details.transformers.find("concat"), details.transformers.end());
}

TEST(DetailsResolver, resolve_transformer_with_list) {
	namespace ast = libsinsp::filter::ast;

	// Build: join(",", (proc.name, proc.pid)) = value
	std::vector<std::unique_ptr<ast::expr>> list_children;
	list_children.push_back(ast::field_expr::create("proc.name", ""));
	list_children.push_back(ast::field_expr::create("proc.pid", ""));

	std::vector<std::unique_ptr<ast::expr>> transformer_args;
	transformer_args.push_back(ast::value_expr::create(","));
	transformer_args.push_back(ast::transformer_list_expr::create(list_children));

	auto filter = ast::binary_check_expr::create(
	        ast::field_transformer_expr::create("join", transformer_args),
	        "=",
	        ast::value_expr::create("value"));

	filter_details details;
	filter_details_resolver resolver;
	resolver.run(filter.get(), details);

	ASSERT_EQ(details.fields.size(), 2);
	ASSERT_NE(details.fields.find("proc.name"), details.fields.end());
	ASSERT_NE(details.fields.find("proc.pid"), details.fields.end());
	ASSERT_EQ(details.transformers.size(), 1);
	ASSERT_NE(details.transformers.find("join"), details.transformers.end());
}

TEST(DetailsResolver, resolve_nested_transformers) {
	namespace ast = libsinsp::filter::ast;

	// Build: toupper(tolower(proc.name)) = value
	auto filter = ast::binary_check_expr::create(
	        ast::field_transformer_expr::create(
	                "toupper",
	                ast::field_transformer_expr::create("tolower",
	                                                    ast::field_expr::create("proc.name", ""))),
	        "=",
	        ast::value_expr::create("value"));

	filter_details details;
	filter_details_resolver resolver;
	resolver.run(filter.get(), details);

	ASSERT_EQ(details.fields.size(), 1);
	ASSERT_NE(details.fields.find("proc.name"), details.fields.end());
	ASSERT_EQ(details.transformers.size(), 2);
	ASSERT_NE(details.transformers.find("toupper"), details.transformers.end());
	ASSERT_NE(details.transformers.find("tolower"), details.transformers.end());
}
