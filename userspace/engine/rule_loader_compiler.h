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

#include "rule_loader.h"
#include "rule_loader_compile_output.h"
#include "rule_loader_collector.h"
#include "filter_macro_resolver.h"
#include "indexed_vector.h"
#include "falco_rule.h"

namespace rule_loader
{

/*!
	\brief Compiler for the ruleset loader of the falco engine
*/
class compiler
{
public:
	compiler() = default;
	virtual ~compiler() = default;
	compiler(compiler&&) = default;
	compiler& operator = (compiler&&) = default;
	compiler(const compiler&) = default;
	compiler& operator = (const compiler&) = default;

	// Return a new result object, suitable for passing to
	// compile().
        virtual std::unique_ptr<compile_output> new_compile_output();

	/*!
		\brief Compiles a list of falco rules
	*/
	virtual void compile(
		configuration& cfg,
		const collector& col,
		compile_output& out) const;
protected:
	 /*!
                \brief Compile a single condition expression,
                including expanding macro and list references.

		returns true if the condition could be compiled, and sets
		ast_out/filter_out with the compiled filter + ast. Returns false if
		the condition could not be compiled and should be skipped.
        */
	bool compile_condition(
		configuration& cfg,
		filter_macro_resolver& macro_resolver,
		indexed_vector<falco_list>& lists,
		const indexed_vector<rule_loader::macro_info>& macros,
		const std::string& condition,
		std::shared_ptr<sinsp_filter_factory> filter_factory,
		const rule_loader::context& cond_ctx,
		const rule_loader::context& parent_ctx,
		bool allow_unknown_fields,
		indexed_vector<falco_macro>& macros_out,
		std::shared_ptr<libsinsp::filter::ast::expr>& ast_out,
		std::shared_ptr<sinsp_filter>& filter_out) const;

private:
	void compile_list_infos(
		configuration& cfg,
		const collector& col,
		indexed_vector<falco_list>& out) const;

	void compile_macros_infos(
		configuration& cfg,
		const collector& col,
		indexed_vector<falco_list>& lists,
		indexed_vector<falco_macro>& out) const;

	void compile_rule_infos(
		configuration& cfg,
		const collector& col,
		indexed_vector<falco_list>& lists,
		indexed_vector<falco_macro>& macros,
		indexed_vector<falco_rule>& out) const;
};

}; // namespace rule_loader

