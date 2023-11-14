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
#include <set>
#include <memory>
#include "falco_common.h"
#include "falco_load_result.h"

/*!
	\brief Searches for bad practices in filter conditions and
	generates warning messages
*/
class filter_warning_resolver
{
public:
	/*!
		\brief Visits a filter AST and substitutes macro references
		according with all the definitions added through set_macro(),
		by replacing the reference with a clone of the macro AST.
		\param filter The filter AST to be visited
		\param warnings Set of strings to be filled with warning codes. This
		is not cleared up before the visit
		\param blocking Filled-out with true if at least one warning is
		found and at least one warning prevents the filter from being loaded
		\return true if at least one warning is generated
	*/
	bool run(
		libsinsp::filter::ast::expr* filter,
		std::set<falco::load_result::warning_code>& warnings) const;

private:
	struct visitor : public libsinsp::filter::ast::base_expr_visitor
	{
		visitor(): m_is_equality_check(false), m_warnings(nullptr) {}
		visitor(visitor&&) = default;
		visitor& operator = (visitor&&) = default;
		visitor(const visitor&) = delete;
		visitor& operator = (const visitor&) = delete;

		bool m_is_equality_check;
		std::set<falco::load_result::warning_code>* m_warnings;

		void visit(libsinsp::filter::ast::value_expr* e) override;
		void visit(libsinsp::filter::ast::list_expr* e) override;
		void visit(libsinsp::filter::ast::binary_check_expr* e) override;
	};
};
