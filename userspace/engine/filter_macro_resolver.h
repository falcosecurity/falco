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
#include <memory>

/*!
	\brief Helper class for substituting and resolving macro
	references in parsed filters.
*/
class filter_macro_resolver
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
		bool run(std::shared_ptr<libsinsp::filter::ast::expr>& filter);

		/*!
			\brief Defines a new macro to be substituted in filters. If called
			multiple times for the same macro name, the previous definition
			gets overridden. A macro can be undefined by setting a null
			AST pointer.
			\param name The name of the macro.
			\param macro The AST of the macro.
		*/
		void set_macro(
			const std::string& name,
			const std::shared_ptr<libsinsp::filter::ast::expr>& macro);

		/*!
		    \brief used in get_{resolved,unknown}_macros and get_errors
			to represent an identifier/string value along with an AST position.
		*/
		typedef std::pair<std::string,libsinsp::filter::ast::pos_info> value_info;

		/*!
			\brief Returns a set containing the names of all the macros
			substituted during the last invocation of run(). Should be
			non-empty if the last invocation of run() returned true.
		*/
		const std::vector<value_info>& get_resolved_macros() const;

		/*!
			\brief Returns a set containing the names of all the macros
			that remained unresolved during the last invocation of run().
			A macro remains unresolved if it is found inside the processed
			filter but it was not defined with set_macro();
		*/
		const std::vector<value_info>& get_unknown_macros() const;

		/*!
			\brief Returns a list of errors occurred during
			the latest invocation of run().
		*/
		const std::vector<value_info>& get_errors() const;

		/*!
			\brief Clears the resolver by resetting all state related to
			known macros and everything related to the previous resolution run.
		*/
		inline void clear()
		{
			m_errors.clear();
			m_unknown_macros.clear();
			m_resolved_macros.clear();
			m_macros.clear();
		}

	private:
		typedef std::unordered_map<
			std::string,
			std::shared_ptr<libsinsp::filter::ast::expr>
		> macro_defs;

		struct visitor : public libsinsp::filter::ast::expr_visitor
		{
			visitor(
				std::vector<value_info>& errors,
				std::vector<value_info>& unknown_macros,
				std::vector<value_info>& resolved_macros,
				macro_defs& macros):
					m_errors(errors),
					m_unknown_macros(unknown_macros),
					m_resolved_macros(resolved_macros),
					m_macros(macros) {}

			std::vector<std::string> m_macros_path;
			std::unique_ptr<libsinsp::filter::ast::expr> m_node_substitute;
			std::vector<value_info>& m_errors;
			std::vector<value_info>& m_unknown_macros;
			std::vector<value_info>& m_resolved_macros;
			macro_defs& m_macros;

			void visit(libsinsp::filter::ast::and_expr* e) override;
			void visit(libsinsp::filter::ast::or_expr* e) override;
			void visit(libsinsp::filter::ast::not_expr* e) override;
			void visit(libsinsp::filter::ast::value_expr* e) override;
			void visit(libsinsp::filter::ast::list_expr* e) override;
			void visit(libsinsp::filter::ast::unary_check_expr* e) override;
			void visit(libsinsp::filter::ast::binary_check_expr* e) override;
		};

		std::vector<value_info> m_errors;
		std::vector<value_info> m_unknown_macros;
		std::vector<value_info> m_resolved_macros;
		macro_defs m_macros;
};
