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
#include <map>
#include <memory>

/*!
	\brief Helper class for substituting and resolving macro
	refereces in parsed filters.
*/
class filter_macro_resolver: private libsinsp::filter::ast::expr_visitor
{
	public:
		/*!
			\brief Visits a filter AST and substitutes macro references
			according with all the definitions added through set_macro(),
			by replacing the reference with a clone of the macro AST.
			\param filter The filter AST to be processed. Note that the pointer
			is passed by reference and be modified in order to apply
			the substutions. In that case, the old pointer is owned by this
			class and is deleted automatically.
			\return true if at least one of the defined macros is resolved
		*/
		bool run(libsinsp::filter::ast::expr*& filter);

		/*!
			\brief Defines a new macro to be substituted in filters. If called
			multiple times for the same macro name, the previous definition
			gets overridden. A macro can be undefined by setting a null
			AST pointer.
			\param name The name of the macro.
			\param macro The AST of the macro.
		*/
		void set_macro(
			std::string name,
			std::shared_ptr<libsinsp::filter::ast::expr> macro);

		/*!
			\brief Returns a set containing the names of all the macros
			substituted during the last invocation of run(). Should be
			non-empty if the last invocation of run() returned true.
		*/
		std::set<std::string>& get_resolved_macros();

		/*!
			\brief Returns a set containing the names of all the macros
			that remained unresolved during the last invocation of run().
			A macro remains unresolved if it is found inside the processed
			filter but it was not defined with set_macro();
		*/
		std::set<std::string>& get_unknown_macros();
		
	private:
		void visit(libsinsp::filter::ast::and_expr* e) override;
		void visit(libsinsp::filter::ast::or_expr* e) override;
		void visit(libsinsp::filter::ast::not_expr* e) override;
		void visit(libsinsp::filter::ast::value_expr* e) override;
		void visit(libsinsp::filter::ast::list_expr* e) override;
		void visit(libsinsp::filter::ast::unary_check_expr* e) override;
		void visit(libsinsp::filter::ast::binary_check_expr* e) override;

		bool m_last_node_changed;
		libsinsp::filter::ast::expr* m_last_node;
		std::set<std::string> m_unknown_macros;
		std::set<std::string> m_resolved_macros;
		std::map<
			std::string,
			std::shared_ptr<libsinsp::filter::ast::expr>
		> m_macros;
};
