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

#include "filter_macro_resolver.h"
#include "falco_common.h"

using namespace libsinsp::filter;

bool filter_macro_resolver::run(std::shared_ptr<libsinsp::filter::ast::expr>& filter)
{
	m_unknown_macros.clear();
	m_resolved_macros.clear();
	m_errors.clear();

	visitor v(m_errors, m_unknown_macros, m_resolved_macros, m_macros);
	v.m_node_substitute = nullptr;
	filter->accept(&v);
	if (v.m_node_substitute)
	{
		filter = std::move(v.m_node_substitute);
	}
	return !m_resolved_macros.empty();
}

void filter_macro_resolver::set_macro(
		const std::string& name,
		const std::shared_ptr<libsinsp::filter::ast::expr>& macro)
{
	m_macros[name] = macro;
}

const std::vector<filter_macro_resolver::value_info>& filter_macro_resolver::get_unknown_macros() const
{
	return m_unknown_macros;
}

const std::vector<filter_macro_resolver::value_info>& filter_macro_resolver::get_errors() const
{
	return m_errors;
}

const std::vector<filter_macro_resolver::value_info>& filter_macro_resolver::get_resolved_macros() const
{
	return m_resolved_macros;
}

void filter_macro_resolver::visitor::visit(ast::and_expr* e)
{
	for (size_t i = 0; i < e->children.size(); i++)
	{
		e->children[i]->accept(this);
		if (m_node_substitute)
		{
			e->children[i] = std::move(m_node_substitute);
		}
	}
	m_node_substitute = nullptr;
}

void filter_macro_resolver::visitor::visit(ast::or_expr* e)
{
	for (size_t i = 0; i < e->children.size(); i++)
	{
		e->children[i]->accept(this);
		if (m_node_substitute)
		{
			e->children[i] = std::move(m_node_substitute);
		}
	}
	m_node_substitute = nullptr;
}

void filter_macro_resolver::visitor::visit(ast::not_expr* e)
{
	e->child->accept(this);
	if (m_node_substitute)
	{
		e->child = std::move(m_node_substitute);
	}
	m_node_substitute = nullptr;
}

void filter_macro_resolver::visitor::visit(ast::list_expr* e)
{
	m_node_substitute = nullptr;
}

void filter_macro_resolver::visitor::visit(ast::binary_check_expr* e)
{
	// avoid exploring checks, so that we can be sure that each
	// value_expr* node visited is a macro identifier
	m_node_substitute = nullptr;
}

void filter_macro_resolver::visitor::visit(ast::unary_check_expr* e)
{
	m_node_substitute = nullptr;
}

void filter_macro_resolver::visitor::visit(ast::value_expr* e)
{
	// we are supposed to get here only in case
	// of identier-only children from either a 'not',
	// an 'and' or an 'or'.
	const auto& macro = m_macros.find(e->value);
	if (macro != m_macros.end() && macro->second) // skip null-ptr macros
	{
		// note: checks for loop detection
		const auto& prevref = std::find(m_macros_path.begin(), m_macros_path.end(), macro->first);
		if (prevref != m_macros_path.end())
		{
			auto msg = "reference loop in macro '" + macro->first + "'";
			m_errors.push_back({msg, e->get_pos()});
			m_node_substitute = nullptr;
			m_unknown_macros.push_back({e->value, e->get_pos()});
			return;
		}

		m_macros_path.push_back(macro->first);
		m_node_substitute = nullptr;
		auto new_node = ast::clone(macro->second.get());
		new_node->accept(this);
		// new_node might already have set a non-NULL m_node_substitute.
		// if not, the right substituted is the newly-cloned node.
		if (!m_node_substitute)
		{
			m_node_substitute = std::move(new_node);
		}
		m_resolved_macros.push_back({e->value, e->get_pos()});
		m_macros_path.pop_back();
	}
	else
	{
		m_node_substitute = nullptr;
		m_unknown_macros.push_back({e->value, e->get_pos()});
	}
}
