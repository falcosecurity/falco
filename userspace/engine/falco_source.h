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

#include <string>
#include "filter_ruleset.h"

/*!
    \brief Represents a given data source used by the engine.
    The ruleset of a source should be created through the ruleset factory
    of the same data source.
*/
struct falco_source {
	falco_source() = default;
	falco_source(falco_source&&) = default;
	falco_source& operator=(falco_source&&) = default;
	falco_source(const falco_source& s):
	        name(s.name),
	        ruleset(s.ruleset),
	        ruleset_factory(s.ruleset_factory),
	        filter_factory(s.filter_factory),
	        formatter_factory(s.formatter_factory) {};
	falco_source& operator=(const falco_source& s) {
		name = s.name;
		ruleset = s.ruleset;
		ruleset_factory = s.ruleset_factory;
		filter_factory = s.filter_factory;
		formatter_factory = s.formatter_factory;
		return *this;
	};

	std::string name;
	std::shared_ptr<filter_ruleset> ruleset;
	std::shared_ptr<filter_ruleset_factory> ruleset_factory;
	std::shared_ptr<sinsp_filter_factory> filter_factory;
	std::shared_ptr<sinsp_evt_formatter_factory> formatter_factory;

	// Used by the filter_ruleset interface. Filled in when a rule
	// matches an event.
	mutable std::vector<falco_rule> m_rules;

	inline bool is_valid_lhs_field(const std::string& field) const {
		// if there's at least one parenthesis we may be parsing a field
		// wrapped inside one or more transformers. In those cases, the most
		// rigorous analysis we can do is compiling a simple filter using
		// the field as left-hand side of a comparison, and see if any error
		// occurs.
		if(field.find('(') != std::string::npos) {
			try {
				auto filter = field;
				filter.append(" exists");
				sinsp_filter_compiler(filter_factory, filter).compile();
				return true;
			} catch(...) {
				return false;
			}
		}

		// otherwise, simply attempt creating a filtercheck with the given
		// field name and see if we succeed
		return filter_factory->new_filtercheck(field.c_str()) != nullptr;
	}
};
