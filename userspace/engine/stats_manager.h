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

#pragma once

#include <vector>
#include <string>
#include "falco_rule.h"
#include "indexed_vector.h"

/*!
	\brief Manager for the internal statistics of the rule engine
*/
class stats_manager
{
public:
	stats_manager();
	virtual ~stats_manager();

	/*!
		\brief Erases the internal state and statistics data
	*/
	virtual void clear();

	/*!
		\brief Callback for when a given rule matches an event
	*/
	virtual void on_event(const falco_rule& rule);

	/*!
		\brief Formats the internal statistics into the out string
	*/
	virtual void format(
		const indexed_vector<falco_rule>& rules,
		std::string& out) const;

private:
	uint64_t m_total;
	std::vector<uint64_t> m_by_priority;
	std::vector<uint64_t> m_by_rule_id;
};