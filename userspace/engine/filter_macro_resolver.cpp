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

#include "filter_macro_resolver.h"

using namespace std;
using namespace libsinsp::filter;

bool filter_macro_resolver::run(libsinsp::filter::ast::expr*& filter)
{
	m_unknown_macros.clear();
	m_resolved_macros.clear();
	m_last_node_changed = false;
	m_last_node = filter;
	filter->accept(this);
	if (m_last_node_changed)
	{
		delete filter;
		filter = m_last_node;
	}
	return !m_resolved_macros.empty();
}

void filter_macro_resolver::set_macro(
		string name,
		shared_ptr<libsinsp::filter::ast::expr> macro)
{
	auto it = m_macros.find(name);
	m_macros[name] = macro;
}

set<string>& filter_macro_resolver::get_unknown_macros()
{
	return m_unknown_macros;
}

set<string>& filter_macro_resolver::get_resolved_macros()
{
	return m_resolved_macros;
}

void filter_macro_resolver::visit(ast::and_expr* e)
{
	for (size_t i = 0; i < e->children.size(); i++)
	{
		e->children[i]->accept(this);
		if (m_last_node_changed)
		{
			delete e->children[i];
			e->children[i] = m_last_node;
		}
	}
	m_last_node = e;
	m_last_node_changed = false;
}

void filter_macro_resolver::visit(ast::or_expr* e)
{
	for (size_t i = 0; i < e->children.size(); i++)
	{
		e->children[i]->accept(this);
		if (m_last_node_changed)
		{
			delete e->children[i];
			e->children[i] = m_last_node;
		}
	}
	m_last_node = e;
	m_last_node_changed = false;
}

void filter_macro_resolver::visit(ast::not_expr* e)
{
	e->child->accept(this);
	if (m_last_node_changed)
	{
		delete e->child;
		e->child = m_last_node;
	}
	m_last_node = e;
	m_last_node_changed = false;
}

void filter_macro_resolver::visit(ast::list_expr* e)
{
	m_last_node = e;
	m_last_node_changed = false;
}

void filter_macro_resolver::visit(ast::binary_check_expr* e)
{
	// avoid exploring checks, so that we can be sure that each
	// value_expr* node visited is a macro identifier
	m_last_node = e;
	m_last_node_changed = false;
}

void filter_macro_resolver::visit(ast::unary_check_expr* e)
{
	m_last_node = e;
	m_last_node_changed = false;
}

void filter_macro_resolver::visit(ast::value_expr* e)
{
	// we are supposed to get here only in case
	// of identier-only children from either a 'not',
	// an 'and' or an 'or'.
	auto macro = m_macros.find(e->value);
	if (macro != m_macros.end())
	{
		ast::expr* new_node = ast::clone(macro->second.get());
		new_node->accept(this); // this sets m_last_node
		m_last_node_changed = true;
		m_resolved_macros.insert(e->value);
	}
	else
	{
		m_last_node = e;
		m_last_node_changed = false;
		m_unknown_macros.insert(e->value);
	}
}
