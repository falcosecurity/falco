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
#include "rule_loader.h"
#include "indexed_vector.h"

namespace rule_loader
{

/*!
	\brief Collector for the ruleset loader of the falco engine
*/
class collector
{
public:
	collector(): m_cur_index(0) { }
	virtual ~collector() = default;
	collector(collector&&) = default;
	collector& operator = (collector&&) = default;
	collector(const collector&) = delete;
	collector& operator = (const collector&) = delete;

	/*!
		\brief Erases all the internal state and definitions
	*/
	virtual void clear();

	/*!
		\brief Returns the set of all defined required plugin versions
	*/
	virtual const std::vector<plugin_version_info::requirement_alternatives>& required_plugin_versions() const;

	/*!
		\brief Returns the required engine versions
	*/
	virtual const engine_version_info& required_engine_version() const;

	/*!
		\brief Returns the list of defined lists
	*/
	virtual const indexed_vector<list_info>& lists() const;

	/*!
		\brief Returns the list of defined macros
	*/
	virtual const indexed_vector<macro_info>& macros() const;

	/*!
		\brief Returns the list of defined rules
	*/
	virtual const indexed_vector<rule_info>& rules() const;

	/*!
		\brief Defines an info block. If a similar info block is found
		in the internal state (e.g. another rule with same name), then
		the previous definition gets overwritten
	*/
	virtual void define(configuration& cfg, engine_version_info& info);
	virtual void define(configuration& cfg, plugin_version_info& info);
	virtual void define(configuration& cfg, list_info& info);
	virtual void define(configuration& cfg, macro_info& info);
	virtual void define(configuration& cfg, rule_info& info);

	/*!
		\brief Appends an info block to an existing one. An exception
		is thrown if no existing definition can be matched with the appended
		one
	*/
	virtual void append(configuration& cfg, list_info& info);
	virtual void append(configuration& cfg, macro_info& info);
	virtual void append(configuration& cfg, rule_update_info& info);

	/*!
		\brief Updates the 'enabled' flag of an existing definition
	*/
	virtual void enable(configuration& cfg, rule_info& info);

	/*!
		\brief Selectively replaces some fields of an existing definition
	*/
	virtual void selective_replace(configuration& cfg, rule_update_info& info);

private:
	uint32_t m_cur_index;
	indexed_vector<rule_info> m_rule_infos;
	indexed_vector<macro_info> m_macro_infos;
	indexed_vector<list_info> m_list_infos;
	std::vector<plugin_version_info::requirement_alternatives> m_required_plugin_versions;
	engine_version_info m_required_engine_version;
};

}; // namespace rule_loader
