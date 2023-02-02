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

/**
 * Given a rule filtering condition (in AST form), the following logic is
 * responsible of returning the set of event types for which the
 * filtering condition can be evaluated to true.
 * 
 * This implementation is based on the boolean algebraic properties of sets 
 * and works as follows depending on the type of nodes:
 * - the evt types of "and" nodes are the intersection set of the evt types of
 *   their children nodes.
 * - the evt types of "or" nodes are the union set of the evt types of
 *   their children nodes.
 * - the evt types of leaf nodes (e.g. "evt.type=open" or "proc.name=cat")
 *   depend on the type of check:
 *   * checks based on evt types (e.g. =xxx, != xxx, in (xxx)) give a clear
 *     definition of the matched event types. The "evt.type exists" check
 *     matches every evt type.
 *   * checks non-related to evt types are neutral and match all evt types
 *     (e.g. proc.name=cat).
 * 
 * The tricky part is handling negation (e.g. "not evt.type=open").
 * Given a set of event types, its negation is the difference between the
 * "set of all events" and the set (e.g. all types but not the ones in the set).
 * Reasonably, negation should not affect checks unrelated to evt types (e.g.
 * "proc.name=cat" is equivalent to "not proc.name=cat" for evt type matching).
 * The knowledge of whether a set of event types should be negated or not
 * can't be handled nor propagated in "and" and "or" nodes. Since rules'
 * conditions are boolean expression, the solution is to use De Morgan's Laws
 * to push the negation evaluations down to the leaf nodes as follows:
 * - "not (A and B)" is evaluated as "not A or not B"
 * - "not (A or B)" is evaluated as "not A and not B"
 * By happening only on leaf nodes, the set of matching event types can safely
 * be constructed and negated depending on the different cases.
 */


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
	// we don't invert "neutral" checks
	if (m_last_node_has_evttypes)
	{
		types = m_all_events.diff(types);
	}
}

void filter_evttype_resolver::visitor::try_inversion(falco_event_types& types)
{
	if (m_inside_negation)
	{
		inversion(types);
	}
}

void filter_evttype_resolver::visitor::evttypes(const std::string& evtname, falco_event_types& out)
{
	for(uint16_t i = PPME_GENERIC_E; i < PPM_EVENT_MAX; i++)
	{
		// Skip unused events
		if(sinsp::is_unused_event(i))
		{
			continue;
		}

		// Fetch event names associated with event id
		const auto evtnames = m_inspector.get_events_names({i});
		for (const auto& name : evtnames)
		{
			// Skip events not matching the requested evtname
			if(evtname.empty() || name == evtname)
			{
				out.insert(i);
			}
		}

	}
}

void filter_evttype_resolver::evttypes(
	ast::expr* filter,
	std::set<uint16_t>& out) const
{
	visitor v;
	filter->accept(&v);
	v.m_last_node_evttypes.for_each([&out](uint16_t val){out.insert(val); return true;});
}

void filter_evttype_resolver::evttypes(
	std::shared_ptr<ast::expr> filter,
	std::set<uint16_t>& out) const
{
	evttypes(filter.get(), out);
}

void filter_evttype_resolver::visitor::conjunction(
	const std::vector<std::unique_ptr<ast::expr>>& children)
{
	falco_event_types types = m_all_events;
	m_last_node_evttypes.clear();
	for (auto &c : children)
	{
		c->accept(this);
		types = types.intersect(m_last_node_evttypes);
	}
	m_last_node_evttypes = types;
}

void filter_evttype_resolver::visitor::disjunction(
	const std::vector<std::unique_ptr<ast::expr>>& children)
{
	falco_event_types types;
	m_last_node_evttypes.clear();
	for (auto &c : children)
	{
		c->accept(this);
		types.merge(m_last_node_evttypes);
	}
	m_last_node_evttypes = types;
}

void filter_evttype_resolver::visitor::visit(ast::and_expr* e)
{
	if (m_inside_negation)
	{
		disjunction(e->children);
	}
	else
	{
		conjunction(e->children);
	}
}

void filter_evttype_resolver::visitor::visit(ast::or_expr* e)
{
	if (m_inside_negation)
	{
		conjunction(e->children);
	}
	else
	{
		disjunction(e->children);
	}
}

void filter_evttype_resolver::visitor::visit(ast::not_expr* e)
{
	m_last_node_evttypes.clear();
	auto inside_negation = m_inside_negation;
	m_inside_negation = !m_inside_negation;
	e->child->accept(this);
	m_inside_negation = inside_negation;
}

void filter_evttype_resolver::visitor::visit(ast::binary_check_expr* e)
{
	m_last_node_evttypes.clear();
	m_last_node_has_evttypes = false;
	if (e->field == "evt.type" && is_evttype_operator(e->op))
	{
		// note: we expect m_inside_negation and m_last_node_has_evttypes
		// to be handled and altered by the child node
		m_expect_value = true;
		e->value->accept(this);
		m_expect_value = false;
		if (e->op == "!=")
		{
			// note: since we push the "negation" down to the tree leaves
			// (following de morgan's laws logic), the child node may have
			// already inverted the set of matched event type. As such,
			// inverting here again is safe for supporting both the
			// single-negation and double-negation cases.
			inversion(m_last_node_evttypes);
		}
		return;
	}
	m_last_node_evttypes = m_all_events;
	try_inversion(m_last_node_evttypes);
}

void filter_evttype_resolver::visitor::visit(ast::unary_check_expr* e)
{
	m_last_node_evttypes.clear();
	m_last_node_has_evttypes = e->field == "evt.type" && e->op == "exists";
	m_last_node_evttypes = m_all_events;
	try_inversion(m_last_node_evttypes);
}

void filter_evttype_resolver::visitor::visit(ast::value_expr* e)
{
	m_last_node_evttypes.clear();
	m_last_node_has_evttypes = m_expect_value;
	if (m_expect_value)
	{
		evttypes(e->value, m_last_node_evttypes);
	}
	else
	{
		// this case only happens if a macro has not yet been substituted
		// with an actual condition. Should not happen, but we handle it
		// for consistency.
		m_last_node_evttypes = m_all_events;
	}
	try_inversion(m_last_node_evttypes);
}

void filter_evttype_resolver::visitor::visit(ast::list_expr* e)
{
	m_last_node_evttypes.clear();
	m_last_node_has_evttypes = false;
	if (m_expect_value)
	{
		m_last_node_has_evttypes = true;
		for (auto &v : e->values)
		{
			evttypes(v, m_last_node_evttypes);
		}
		try_inversion(m_last_node_evttypes);
		return;
	}
	m_last_node_evttypes = m_all_events;
	try_inversion(m_last_node_evttypes);
}
