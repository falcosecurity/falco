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

using namespace libsinsp::filter;

std::string get_field_name(const std::string& name, const std::string& arg)
{
	std::string fld = name;
	if (!arg.empty())
	{
		fld += "[" + arg + "]";
	}
	return fld;
}

void filter_details::reset()
{
	fields.clear();
	macros.clear();
	operators.clear();
	lists.clear();
	evtnames.clear();
}

void filter_details_resolver::run(ast::expr* filter, filter_details& details)
{
	visitor v(details);
	filter->accept(&v);
}

void filter_details_resolver::visitor::visit(ast::and_expr* e)
{
	for(size_t i = 0; i < e->children.size(); i++)
	{
		m_expect_macro = true;
		e->children[i]->accept(this);
		m_expect_macro = false;
	}
}

void filter_details_resolver::visitor::visit(ast::or_expr* e)
{
	for(size_t i = 0; i < e->children.size(); i++)
	{
		m_expect_macro = true;
		e->children[i]->accept(this);
		m_expect_macro = false;
	}
}

void filter_details_resolver::visitor::visit(ast::not_expr* e)
{
	e->child->accept(this);
}

void filter_details_resolver::visitor::visit(ast::list_expr* e)
{
	if(m_expect_list)
	{
		for(const auto& item : e->values)
		{
			if(m_details.known_lists.find(item) != m_details.known_lists.end())
			{
				m_details.lists.insert(item);
			}
		}
	}
	if (m_expect_evtname)
	{
		for(const auto& item : e->values)
		{
			if(m_details.known_lists.find(item) == m_details.known_lists.end())
			{
				m_details.evtnames.insert(item);
			}
		}
	}
}

void filter_details_resolver::visitor::visit(ast::binary_check_expr* e)
{
	m_expect_macro = false;
	m_details.fields.insert(get_field_name(e->field, e->arg));
	m_details.operators.insert(e->op);
	if (e->field == "evt.type" || e->field == "evt.asynctype")
	{
		m_expect_evtname = true;
		e->value->accept(this);
		m_expect_evtname = false;
	}
	else
	{
		m_expect_list = true;
		e->value->accept(this);
		m_expect_list = false;
	}
}

void filter_details_resolver::visitor::visit(ast::unary_check_expr* e)
{
	m_expect_macro = false;
	m_details.fields.insert(get_field_name(e->field, e->arg));
	m_details.operators.insert(e->op);
}

void filter_details_resolver::visitor::visit(ast::value_expr* e)
{
	if(m_expect_macro)
	{
		auto it = m_details.known_macros.find(e->value);
		if(it == m_details.known_macros.end())
		{
			return;
		}

		m_details.macros.insert(e->value);
	}
	if(m_expect_evtname)
	{
		m_details.evtnames.insert(e->value);
	}
}
