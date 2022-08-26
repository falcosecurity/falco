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

#include "stats_manager.h"
#include "falco_common.h"

using namespace std;

stats_manager::stats_manager()
	: m_total(0)
{
}

stats_manager::~stats_manager()
{
	clear();
}

void stats_manager::clear()
{
	m_total = 0;
	m_by_rule_id.clear();
	m_by_priority.clear();
}

void stats_manager::format(
	const indexed_vector<falco_rule>& rules,
	string& out) const
{
	string fmt;
	out = "Events detected: " + to_string(m_total) + "\n";
	out += "Rule counts by severity:\n";
	for (size_t i = 0; i < m_by_priority.size(); i++)
	{
		auto val = m_by_priority[i].get()->load();
		if (val > 0)
		{
			falco_common::format_priority(
				(falco_common::priority_type) i, fmt, true);
			transform(fmt.begin(), fmt.end(), fmt.begin(), ::toupper);
			out += "   " + fmt + ": " + to_string(val) + "\n";
		}
	}
	out += "Triggered rules by rule name:\n";
	for (size_t i = 0; i < m_by_rule_id.size(); i++)
	{
		auto val = m_by_rule_id[i].get()->load();
		if (val > 0)
		{
			out += "   " + rules.at(i)->name + ": " + to_string(val) + "\n";
		}
	}
}

void stats_manager::on_rule_loaded(const falco_rule& rule)
{
	while (m_by_rule_id.size() <= rule.id)
	{
		m_by_rule_id.emplace_back();
		m_by_rule_id[m_by_rule_id.size() - 1].reset(new atomic<uint64_t>(0));
	}
	while (m_by_priority.size() <= (size_t) rule.priority)
	{
		m_by_priority.emplace_back();
		m_by_priority[m_by_priority.size() - 1].reset(new atomic<uint64_t>(0));
	}
}

void stats_manager::on_event(const falco_rule& rule)
{
	if (m_by_rule_id.size() <= rule.id
		|| m_by_priority.size() <= (size_t) rule.priority)
	{
		throw falco_exception("rule id or priority is out of boubnds");
	}
	m_total.fetch_add(1, std::memory_order_relaxed);
	m_by_rule_id[rule.id]->fetch_add(1, std::memory_order_relaxed);
	m_by_priority[(size_t) rule.priority]->fetch_add(1, std::memory_order_relaxed);
}
