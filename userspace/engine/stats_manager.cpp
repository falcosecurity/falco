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

void stats_manager::clear()
{
	m_total = 0;
	m_by_rule_id.clear();
	m_by_priority.clear();
}

void stats_manager::format(
	const indexed_vector<falco_rule>& rules,
	string& out)
{
	string fmt;
	string name;
	out = "Events detected: " + to_string(m_total) + "\n";
	out += "Rule counts by severity:\n";
	for (size_t i = 0; i < m_by_priority.size(); i++)
	{
		if (m_by_priority[i] > 0)
		{
			falco_common::format_priority((falco_common::priority_type) i, fmt);
			transform(fmt.begin(), fmt.end(), fmt.begin(), ::toupper);
			out += "   " + fmt;
			out += ": " + to_string(m_by_priority[i]) + "\n";
		}
	}
	out += "Triggered rules by rule name:\n";
	for (size_t i = 0; i < m_by_rule_id.size(); i++)
	{
		if (m_by_rule_id[i] > 0)
		{
			out += "   " + rules.at(i)->name;
			out += ": " + to_string(m_by_rule_id[i]) + "\n";
		}
	}
}

void stats_manager::on_event(
		const indexed_vector<falco_rule>& rules,
		uint32_t rule_id)
{
	auto *rule = rules.at(rule_id);
	if (!rule)
	{
		throw falco_exception(
			"on_event(): event with invalid rule_id: " + rule_id);
	}
	if (m_by_rule_id.size() <= rule_id)
	{
		m_by_rule_id.resize(rule_id + 1);
		m_by_rule_id[rule_id] = 0;
	}
	if (m_by_priority.size() <= (size_t) rule->priority)
	{
		m_by_priority.resize((size_t) rule->priority + 1);
		m_by_priority[(size_t) rule->priority] = 0;
	}
	m_total++;
	m_by_rule_id[rule_id]++;
	m_by_priority[(size_t) rule->priority]++;
}
