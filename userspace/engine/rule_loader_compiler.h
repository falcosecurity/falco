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

#include "rule_loader.h"
#include "rule_loader_collector.h"
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
	virtual ~compiler() = default;

	/*!
		\brief Compiles a list of falco rules
	*/
	virtual void compile(
		configuration& cfg,
		const collector& col,
		indexed_vector<falco_rule>& out) const;

private:
	void compile_list_infos(
		configuration& cfg,
		const collector& col,
		indexed_vector<list_info>& out) const;

	void compile_macros_infos(
		configuration& cfg,
		const collector& col,
		indexed_vector<list_info>& lists,
		indexed_vector<macro_info>& out) const;

	void compile_rule_infos(
		configuration& cfg,
		const collector& col,
		indexed_vector<list_info>& lists,
		indexed_vector<macro_info>& macros,
		indexed_vector<falco_rule>& out) const;
};

}; // namespace rule_loader

