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

using namespace std;
using namespace libsinsp::filter;

extern sinsp_evttables g_infotables;

static bool is_evttype_operator(const string& op)
{
	return op == "==" || op == "=" || op == "!=" || op == "in";
}

void filter_evttype_resolver::evttypes(string evtname, set<uint16_t>& out)
{
	// Fill in from 2 to PPM_EVENT_MAX-1. 0 and 1 are excluded as
	// those are PPM_GENERIC_E/PPME_GENERIC_X.
	const struct ppm_event_info* etable = g_infotables.m_event_info;
	for(uint16_t i = 2; i < PPM_EVENT_MAX; i++)
	{
		// Skip "old" event versions that have been replaced
		// by newer event versions, or events that are unused.
		if(!(etable[i].flags & (EF_OLD_VERSION | EF_UNUSED))
			&& (evtname.empty() || string(etable[i].name) == evtname))
		{
			out.insert(i);
		}
	}
}

void filter_evttype_resolver::evttypes(ast::expr* filter, set<uint16_t>& out)
{
	m_expect_value = false;
	m_last_node_evttypes.clear();
	filter->accept(this);
	copy(m_last_node_evttypes.begin(),
		m_last_node_evttypes.end(),
		inserter(out, out.begin()));
}

void filter_evttype_resolver::evttypes(
	shared_ptr<ast::expr> filter, set<uint16_t>& out)
{
	m_expect_value = false;
	m_last_node_evttypes.clear();
	filter.get()->accept(this);
	copy(m_last_node_evttypes.begin(),
		m_last_node_evttypes.end(),
		inserter(out, out.begin()));
}

void filter_evttype_resolver::visit(ast::and_expr* e)
{
	set<uint16_t> nodetypes;
	evttypes("", nodetypes);
	m_last_node_evttypes.clear();
	for (auto &c : e->children)
	{
		set<uint16_t> inters;
		c->accept(this);
		set_intersection(
			nodetypes.begin(), nodetypes.end(),
			m_last_node_evttypes.begin(), m_last_node_evttypes.end(),
			std::inserter(inters, inters.begin()));
		nodetypes = inters;
	}
	m_last_node_evttypes = nodetypes;
}

void filter_evttype_resolver::visit(ast::or_expr* e)
{
	set<uint16_t> nodetypes;
	m_last_node_evttypes.clear();
	for (auto &c : e->children)
	{
		c->accept(this);
		copy(m_last_node_evttypes.begin(),
			m_last_node_evttypes.end(),
			inserter(nodetypes, nodetypes.begin()));
	}
	m_last_node_evttypes = nodetypes;
}

void filter_evttype_resolver::visit(ast::not_expr* e)
{
	set<uint16_t> diff, all_types;
	m_last_node_evttypes.clear();
	e->child->accept(this);
	evttypes("", all_types);
	if (all_types != m_last_node_evttypes)
	{
		diff = m_last_node_evttypes;
		m_last_node_evttypes.clear();
		set_difference(
			all_types.begin(), all_types.end(), diff.begin(), diff.end(),
			inserter(m_last_node_evttypes, m_last_node_evttypes.begin()));
	}
}

void filter_evttype_resolver::visit(ast::binary_check_expr* e)
{
	m_last_node_evttypes.clear();
	if (e->field == "evt.type" && is_evttype_operator(e->op))
	{
		m_expect_value = true;
		e->value->accept(this);
		m_expect_value = false;
		if (e->op == "!=")
		{
			set<uint16_t> all_types;
			set<uint16_t> diff = m_last_node_evttypes;
			m_last_node_evttypes.clear();
			evttypes("", all_types);
			set_difference(
				all_types.begin(), all_types.end(), diff.begin(), diff.end(),
				inserter(m_last_node_evttypes, m_last_node_evttypes.begin()));
		}
		return;
	}
	evttypes("", m_last_node_evttypes);
}

void filter_evttype_resolver::visit(ast::unary_check_expr* e)
{
	m_last_node_evttypes.clear();
	evttypes("", m_last_node_evttypes);
}

void filter_evttype_resolver::visit(ast::value_expr* e)
{
	m_last_node_evttypes.clear();
	if (m_expect_value)
	{
		evttypes(e->value, m_last_node_evttypes);
		return;
	}
	evttypes("", m_last_node_evttypes);
}

void filter_evttype_resolver::visit(ast::list_expr* e)
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
