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
#include "rule_loader.h"

/*!
    \brief Searches for bad practices in filter conditions and
    generates warning messages
*/
class filter_warning_resolver {
public:
	/*!
	    \brief Runs the filter warning resolver on a filter AST and adds the warnings to the result
	   object \param ctx The context of the warning \param res The result to add the warnings to
	    \param filter The filter AST to be visited
	    \return true if at least one warning is generated
	*/
	bool run(const rule_loader::context& ctx,
	         rule_loader::result& res,
	         libsinsp::filter::ast::expr& filter) const;

private:
	struct visitor : public libsinsp::filter::ast::base_expr_visitor {
		visitor(std::set<falco::load_result::warning_code>& warnings,
		        std::set<falco::load_result::deprecated_field>& deprecated_fields):
		        m_is_equality_check(false),
		        m_last_node_is_unsafe_field(false),
		        m_warnings(&warnings),
		        m_deprecated_fields(&deprecated_fields) {}
		visitor(visitor&&) = default;
		visitor& operator=(visitor&&) = default;
		visitor(const visitor&) = delete;
		visitor& operator=(const visitor&) = delete;

		bool m_is_equality_check;
		bool m_last_node_is_unsafe_field;
		std::set<falco::load_result::warning_code>* m_warnings;
		std::set<falco::load_result::deprecated_field>* m_deprecated_fields;

		void visit(libsinsp::filter::ast::value_expr* e) override;
		void visit(libsinsp::filter::ast::list_expr* e) override;
		void visit(libsinsp::filter::ast::binary_check_expr* e) override;
		void visit(libsinsp::filter::ast::field_expr* e) override;
	};
};
