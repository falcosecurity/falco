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

#pragma once

#include <libsinsp/filter/parser.h>
#include <string>
#include <unordered_set>
#include <unordered_map>

struct filter_details
{
	// input macros and lists
	std::unordered_set<std::string> known_macros;
	std::unordered_set<std::string> known_lists;

	// output details
	std::unordered_set<std::string> fields;
	std::unordered_set<std::string> macros;
	std::unordered_set<std::string> operators;
	std::unordered_set<std::string> lists;
	std::unordered_set<std::string> evtnames;

	void reset();
};

/*!
	\brief Helper class for getting details about rules' filters.
*/
class filter_details_resolver
{
public:
	/*!
		\brief Visits a filter AST and stores details about macros, lists,
		fields and operators used.
		\param filter The filter AST to be processed.
		\param details Helper structure used to state known macros and
		lists on input, and to store all the retrieved details as output.
	*/
	void run(libsinsp::filter::ast::expr* filter,
		filter_details& details);

private:
	struct visitor : public libsinsp::filter::ast::expr_visitor
	{
		explicit visitor(filter_details& details) :
			m_details(details),
			m_expect_list(false),
			m_expect_macro(false),
			m_expect_evtname(false) {}
		visitor(visitor&&) = default;
		visitor(const visitor&) = delete;

		void visit(libsinsp::filter::ast::and_expr* e) override;
		void visit(libsinsp::filter::ast::or_expr* e) override;
		void visit(libsinsp::filter::ast::not_expr* e) override;
		void visit(libsinsp::filter::ast::value_expr* e) override;
		void visit(libsinsp::filter::ast::list_expr* e) override;
		void visit(libsinsp::filter::ast::unary_check_expr* e) override;
		void visit(libsinsp::filter::ast::binary_check_expr* e) override;

		filter_details& m_details;
		bool m_expect_list;
		bool m_expect_macro;
		bool m_expect_evtname;
	};
};
