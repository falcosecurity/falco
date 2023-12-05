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

#pragma once

#include <vector>
#include <string>
#include <atomic>
#include <memory>
#include "falco_rule.h"
#include "indexed_vector.h"

/*!
	\brief Manager for the internal statistics of the rule engine.
	The on_event() is thread-safe and non-blocking, and it can be used
	concurrently across many callers in parallel.
	All the other methods are not thread safe.
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
		\brief Callback for when a new rule is loaded in the engine.
		Rules must be passed through this method before submitting them as
		an argument of on_event().
	*/
	virtual void on_rule_loaded(const falco_rule& rule);

	/*!
		\brief Callback for when a given rule matches an event.
		This method is thread-safe.
		\throws falco_exception if rule has not been passed to
		on_rule_loaded() first
	*/
	virtual void on_event(const falco_rule& rule);

	/*!
		\brief Formats the internal statistics into the out string.
	*/
	virtual void format(
		const indexed_vector<falco_rule>& rules,
		std::string& out) const;

private:
	std::atomic<uint64_t> m_total;
	std::vector<std::unique_ptr<std::atomic<uint64_t>>> m_by_priority;
	std::vector<std::unique_ptr<std::atomic<uint64_t>>> m_by_rule_id;
};
