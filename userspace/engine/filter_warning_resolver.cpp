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

#include <string>
#include <libsinsp/sinsp.h>
#include "filter_warning_resolver.h"

using namespace falco;

static const char* no_value = "<NA>";

static inline bool is_unsafe_field(const std::string& f) {
	return !strncmp(f.c_str(), "ka.", strlen("ka.")) ||
	       !strncmp(f.c_str(), "jevt.", strlen("jevt."));
}

static inline bool is_equality_operator(const std::string& op) {
	return op == "==" || op == "=" || op == "!=" || op == "in" || op == "intersects" ||
	       op == "pmatch";
}

bool filter_warning_resolver::run(const rule_loader::context& ctx,
                                  rule_loader::result& res,
                                  libsinsp::filter::ast::expr& filter) const {
	std::set<falco::load_result::warning_code> warnings;
	std::set<falco::load_result::deprecated_field> deprecated_fields;
	visitor v(warnings, deprecated_fields);
	v.m_is_equality_check = false;
	filter.accept(&v);
	for(auto& w : warnings) {
		switch(w) {
		case falco::load_result::warning_code::LOAD_DEPRECATED_ITEM:
			// add a warning for each deprecated field
			for(auto& deprecated_field : deprecated_fields) {
				res.add_deprecated_field_warning(
				        deprecated_field,
				        falco::load_result::deprecated_field_desc(deprecated_field),
				        ctx);
			}
			break;
		default:
			res.add_warning(w, "", ctx);
		}
	}
	return !warnings.empty();
}

void filter_warning_resolver::visitor::visit(libsinsp::filter::ast::binary_check_expr* e) {
	m_last_node_is_unsafe_field = false;
	e->left->accept(this);
	if(m_last_node_is_unsafe_field && is_equality_operator(e->op)) {
		m_is_equality_check = true;
		e->right->accept(this);
		m_is_equality_check = false;
	}
}

void filter_warning_resolver::visitor::visit(libsinsp::filter::ast::field_expr* e) {
	m_last_node_is_unsafe_field = is_unsafe_field(e->field);

	// Check for deprecated dir field usage
	if(auto df = falco::load_result::deprecated_field_from_str(e->field);
	   df != falco::load_result::deprecated_field::DEPRECATED_FIELD_NOT_FOUND) {
		m_deprecated_fields->insert(df);
		m_warnings->insert(falco::load_result::warning_code::LOAD_DEPRECATED_ITEM);
	}
}

void filter_warning_resolver::visitor::visit(libsinsp::filter::ast::value_expr* e) {
	if(m_is_equality_check && e->value == no_value) {
		m_warnings->insert(falco::load_result::warning_code::LOAD_UNSAFE_NA_CHECK);
	}
}

void filter_warning_resolver::visitor::visit(libsinsp::filter::ast::list_expr* e) {
	if(m_is_equality_check &&
	   std::find(e->values.begin(), e->values.end(), no_value) != e->values.end()) {
		m_warnings->insert(falco::load_result::warning_code::LOAD_UNSAFE_NA_CHECK);
	}
}
