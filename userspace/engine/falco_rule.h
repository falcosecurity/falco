// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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
struct falco_list {
	falco_list(): used(false), id(0) {}
	falco_list(falco_list&&) = default;
	falco_list& operator=(falco_list&&) = default;
	falco_list(const falco_list&) = default;
	falco_list& operator=(const falco_list&) = default;
	~falco_list() = default;

	bool operator==(const falco_list& rhs) const {
		return (this->used == rhs.used && this->id == rhs.id && this->name == rhs.name &&
		        this->items == rhs.items);
	}

	bool used;
	std::size_t id;
	std::string name;
	std::vector<std::string> items;
};

/*!
    \brief Represents a macro in the Falco Engine.
    The rule ID must be unique across all the macros loaded in the engine.
*/
struct falco_macro {
	falco_macro(): used(false), id(0) {}
	falco_macro(falco_macro&&) = default;
	falco_macro& operator=(falco_macro&&) = default;
	falco_macro(const falco_macro&) = default;
	falco_macro& operator=(const falco_macro&) = default;
	~falco_macro() = default;

	bool operator==(const falco_macro& rhs) const {
		// Note this only ensures that the shared_ptrs are
		// pointing to the same underlying memory, not that
		// they are logically equal.
		return (this->used == rhs.used && this->id == rhs.id && this->name == rhs.name &&
		        this->condition.get() == rhs.condition.get());
	}

	bool used;
	std::size_t id;
	std::string name;
	std::shared_ptr<libsinsp::filter::ast::expr> condition;
};

/*!
    \brief Represents a rule in the Falco Engine.
    The rule ID must be unique across all the rules loaded in the engine.
*/
struct falco_rule {
	falco_rule():
	        id(0),
	        priority(falco_common::PRIORITY_DEBUG),
	        capture(false),
	        capture_duration(0) {}
	falco_rule(falco_rule&&) = default;
	falco_rule& operator=(falco_rule&&) = default;
	falco_rule(const falco_rule&) = default;
	falco_rule& operator=(const falco_rule&) = default;
	~falco_rule() = default;

	bool operator==(const falco_rule& rhs) const {
		// Note this only ensures that the shared_ptrs are
		// pointing to the same underlying memory, not that
		// they are logically equal.
		return (this->id == rhs.id && this->source == rhs.source && this->name == rhs.name &&
		        this->description == rhs.description && this->output == rhs.output &&
		        this->tags == rhs.tags && this->exception_fields == rhs.exception_fields &&
		        this->priority == rhs.priority && this->capture == rhs.capture &&
		        this->capture_duration == rhs.capture_duration &&
		        this->condition.get() == rhs.condition.get() &&
		        this->filter.get() == rhs.filter.get());
	}

	std::size_t id;
	std::string source;
	std::string name;
	std::string description;
	std::string output;
	extra_output_field_t extra_output_fields;
	std::set<std::string> tags;
	std::set<std::string> exception_fields;
	falco_common::priority_type priority;
	bool capture;
	uint32_t capture_duration;
	std::shared_ptr<libsinsp::filter::ast::expr> condition;
	std::shared_ptr<sinsp_filter> filter;
};
