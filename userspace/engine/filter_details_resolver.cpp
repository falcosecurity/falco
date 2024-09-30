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

#include "filter_details_resolver.h"

#include <stdexcept>

using namespace libsinsp::filter;

static inline std::string get_field_name(const std::string& name, const std::string& arg) {
	std::string fld = name;
	if(!arg.empty()) {
		fld += "[" + arg + "]";
	}
	return fld;
}

void filter_details::reset() {
	fields.clear();
	macros.clear();
	operators.clear();
	lists.clear();
	evtnames.clear();
	transformers.clear();
}

void filter_details_resolver::run(ast::expr* filter, filter_details& details) {
	visitor v(details);
	filter->accept(&v);
}

void filter_details_resolver::visitor::visit(ast::and_expr* e) {
	for(size_t i = 0; i < e->children.size(); i++) {
		e->children[i]->accept(this);
	}
}

void filter_details_resolver::visitor::visit(ast::or_expr* e) {
	for(size_t i = 0; i < e->children.size(); i++) {
		e->children[i]->accept(this);
	}
}

void filter_details_resolver::visitor::visit(ast::not_expr* e) {
	e->child->accept(this);
}

void filter_details_resolver::visitor::visit(ast::list_expr* e) {
	if(m_expect_list) {
		for(const auto& item : e->values) {
			if(m_details.known_lists.find(item) != m_details.known_lists.end()) {
				m_details.lists.insert(item);
			}
		}
	}
	if(m_expect_evtname) {
		for(const auto& item : e->values) {
			if(m_details.known_lists.find(item) == m_details.known_lists.end()) {
				m_details.evtnames.insert(item);
			}
		}
	}
}

void filter_details_resolver::visitor::visit(ast::binary_check_expr* e) {
	m_last_node_field_name.clear();
	m_expect_evtname = false;
	m_expect_list = false;
	e->left->accept(this);
	if(m_last_node_field_name.empty()) {
		throw std::runtime_error("can't find field info in binary check expression");
	}

	m_details.operators.insert(e->op);

	m_expect_list = true;
	m_expect_evtname =
	        m_last_node_field_name == "evt.type" || m_last_node_field_name == "evt.asynctype";
	e->right->accept(this);
	m_expect_evtname = false;
	m_expect_list = false;
}

void filter_details_resolver::visitor::visit(ast::unary_check_expr* e) {
	m_last_node_field_name.clear();
	e->left->accept(this);
	if(m_last_node_field_name.empty()) {
		throw std::runtime_error("can't find field info in unary check expression");
	}
	m_details.fields.insert(m_last_node_field_name);
	m_details.operators.insert(e->op);
}

void filter_details_resolver::visitor::visit(ast::identifier_expr* e) {
	// todo(jasondellaluce): maybe throw an error if we encounter an unknown macro?
	if(m_details.known_macros.find(e->identifier) != m_details.known_macros.end()) {
		m_details.macros.insert(e->identifier);
	}
}

void filter_details_resolver::visitor::visit(ast::value_expr* e) {
	if(m_expect_evtname) {
		m_details.evtnames.insert(e->value);
	}
}

void filter_details_resolver::visitor::visit(ast::field_expr* e) {
	m_last_node_field_name = get_field_name(e->field, e->arg);
	m_details.fields.insert(m_last_node_field_name);
}

void filter_details_resolver::visitor::visit(ast::field_transformer_expr* e) {
	m_details.transformers.insert(e->transformer);
	e->value->accept(this);
}
