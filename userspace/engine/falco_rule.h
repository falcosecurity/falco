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

#include <set>
#include <string>
#include "falco_common.h"

#include <libsinsp/filter/ast.h>

/*!
	\brief Represents a list in the Falco Engine.
	The rule ID must be unique across all the lists loaded in the engine.
*/
struct falco_list
{
	falco_list(): used(false), id(0) { }
	falco_list(falco_list&&) = default;
	falco_list& operator = (falco_list&&) = default;
	falco_list(const falco_list&) = default;
	falco_list& operator = (const falco_list&) = default;
	~falco_list() = default;

	bool used;
	std::size_t id;
	std::string name;
	std::vector<std::string> items;
};

/*!
	\brief Represents a macro in the Falco Engine.
	The rule ID must be unique across all the macros loaded in the engine.
*/
struct falco_macro
{
	falco_macro(): used(false), id(0) { }
	falco_macro(falco_macro&&) = default;
	falco_macro& operator = (falco_macro&&) = default;
	falco_macro(const falco_macro&) = default;
	falco_macro& operator = (const falco_macro&) = default;
	~falco_macro() = default;

	bool used;
	std::size_t id;
	std::string name;
	std::shared_ptr<libsinsp::filter::ast::expr> condition;
};

/*!
	\brief Represents a rule in the Falco Engine.
	The rule ID must be unique across all the rules loaded in the engine.
*/
struct falco_rule
{
	falco_rule(): id(0), priority(falco_common::PRIORITY_DEBUG) {}
	falco_rule(falco_rule&&) = default;
	falco_rule& operator = (falco_rule&&) = default;
	falco_rule(const falco_rule&) = default;
	falco_rule& operator = (const falco_rule&) = default;
	~falco_rule() = default;

	std::size_t id;
	std::string source;
	std::string name;
	std::string description;
	std::string output;
	std::set<std::string> tags;
	std::set<std::string> exception_fields;
	falco_common::priority_type priority;
	std::shared_ptr<libsinsp::filter::ast::expr> condition;
	std::shared_ptr<sinsp_filter> filter;
};
