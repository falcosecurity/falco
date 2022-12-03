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

#include "filter_evttype_resolver.h"
#include <sinsp.h>

using namespace libsinsp::filter;

extern sinsp_evttables g_infotables;

static bool is_evttype_operator(const std::string& op)
{
	return op == "==" || op == "=" || op == "!=" || op == "in";
}


size_t falco_event_types::get_ppm_event_max()
{
	return PPM_EVENT_MAX;
}

void filter_evttype_resolver::visitor::inversion(falco_event_types& types)
{
	falco_event_types all_types;
	evttypes("", all_types);
	if (types != all_types) // we don't invert the "all types" set
	{
		types = all_types.diff(types);
	}
}

void filter_evttype_resolver::visitor::evttypes(const std::string& evtname, falco_event_types& out)
{
	// Fill in from 2 to PPM_EVENT_MAX-1. 0 and 1 are excluded as
	// those are PPM_GENERIC_E/PPME_GENERIC_X
	const struct ppm_event_info* etable = g_infotables.m_event_info;
	for(uint16_t i = 2; i < PPM_EVENT_MAX; i++)
	{
		// Skip unused events or events not matching the requested evtname
		if(!sinsp::is_unused_event(i) && (evtname.empty() || std::string(etable[i].name) == evtname))
		{
			out.insert(i);
		}
	}
}

void filter_evttype_resolver::evttypes(
	ast::expr* filter,
	std::set<uint16_t>& out) const
{
	visitor v;
	v.m_expect_value = false;
	v.m_last_node_evttypes.clear();
	filter->accept(&v);
	v.m_last_node_evttypes.for_each([&out](uint16_t val){out.insert(val); return true;});
}

void filter_evttype_resolver::evttypes(
	std::shared_ptr<ast::expr> filter,
	std::set<uint16_t>& out) const
{
	visitor v;
	v.m_expect_value = false;
	v.m_last_node_evttypes.clear();
	filter.get()->accept(&v);
	v.m_last_node_evttypes.for_each([&out](uint16_t val){out.insert(val); return true;} );
}

// "and" nodes evttypes are the intersection of the evttypes of their children.
// we initialize the set with "all event types"
void filter_evttype_resolver::visitor::visit(ast::and_expr* e)
{
	falco_event_types types;
	evttypes("", types);
	m_last_node_evttypes.clear();
	for (auto &c : e->children)
	{
		falco_event_types inters;
		c->accept(this);
		types = types.intersect(m_last_node_evttypes);
	}
	m_last_node_evttypes = types;
}

// "or" nodes evttypes are the union of the evttypes their children
void filter_evttype_resolver::visitor::visit(ast::or_expr* e)
{
	falco_event_types types;
	m_last_node_evttypes.clear();
	for (auto &c : e->children)
	{
		c->accept(this);
		types.merge(m_last_node_evttypes);
	}
	m_last_node_evttypes = types;
}

void filter_evttype_resolver::visitor::visit(ast::not_expr* e)
{
	m_last_node_evttypes.clear();
	e->child->accept(this);
	inversion(m_last_node_evttypes);
}

void filter_evttype_resolver::visitor::visit(ast::binary_check_expr* e)
{
	m_last_node_evttypes.clear();
	if (e->field == "evt.type" && is_evttype_operator(e->op))
	{
		m_expect_value = true;
		e->value->accept(this);
		m_expect_value = false;
		if (e->op == "!=")
		{
			inversion(m_last_node_evttypes);
		}
		return;
	}
	evttypes("", m_last_node_evttypes);
}

void filter_evttype_resolver::visitor::visit(ast::unary_check_expr* e)
{
	m_last_node_evttypes.clear();
	evttypes("", m_last_node_evttypes);
}

void filter_evttype_resolver::visitor::visit(ast::value_expr* e)
{
	m_last_node_evttypes.clear();
	if (m_expect_value)
	{
		evttypes(e->value, m_last_node_evttypes);
		return;
	}
	evttypes("", m_last_node_evttypes);
}

void filter_evttype_resolver::visitor::visit(ast::list_expr* e)
{
	m_last_node_evttypes.clear();
	if (m_expect_value)
	{
		for (auto &v : e->values)
		{
			evttypes(v, m_last_node_evttypes);
		}	
		return;
	}
	evttypes("", m_last_node_evttypes);
}
