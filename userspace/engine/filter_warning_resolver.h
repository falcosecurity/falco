/*
Copyright (C) 2022 The Falco Authors.

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

#include <filter/parser.h>
#include <string>
#include <set>
#include <memory>
#include "falco_common.h"

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
		std::set<std::string>& warnings) const;
	
	/*!
		\brief Given a warning code retrieved through run(), returns
		a verbose message describing the problem of the warning.
		\param code The warning code string
		\param out The string to be filled-out with the warning message
		\return true if the warning code is recognized, false otherwise
	*/
	bool format(const std::string& code, std::string& out) const;

	/*!
		\brief Given a warning code retrieved through run(), returns
		a verbose message describing the problem of the warning.
		\param code The warning code string
		\return The warning message string
		\throw falco_exception if the warning code is not recognized

	*/
	inline std::string format(const std::string& code) const
	{
		std::string v;
		if (!format(code, v))
		{
			throw falco_exception("unrecognized warning code: " + code);
		}
		return v;
	}

private:
	struct visitor : public libsinsp::filter::ast::base_expr_visitor
	{
		bool m_is_equality_check;
		std::set<std::string>* m_warnings;

		void visit(libsinsp::filter::ast::value_expr* e) override;
		void visit(libsinsp::filter::ast::list_expr* e) override;
		void visit(libsinsp::filter::ast::binary_check_expr* e) override;
	};
};
