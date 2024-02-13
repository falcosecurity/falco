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

#include "falco_rule.h"
#include "rule_loader_compile_output.h"
#include <libsinsp/filter/ast.h>
#include <libsinsp/filter.h>
#include <libsinsp/event.h>
#include <libsinsp/events/sinsp_events.h>

/*!
	\brief Manages a set of rulesets. A ruleset is a set of
	enabled rules that is able to process events and find matches for those rules.
*/

class filter_ruleset
{
public:
	// A set of functions that can be used to retrieve state from
	// the falco engine that created this ruleset.
	struct engine_state_funcs
	{
		using ruleset_retriever_func_t = std::function<bool(const std::string &, std::shared_ptr<filter_ruleset> &ruleset)>;

		ruleset_retriever_func_t get_ruleset;
	};

	virtual ~filter_ruleset() = default;

	void set_engine_state(const engine_state_funcs &engine_state);
	engine_state_funcs &get_engine_state();

	/*!
		\brief Adds a rule and its filtering filter + condition inside the manager.
	        This method only adds the rule inside the internal collection,
		but does not enable it for any ruleset.	The rule must be enabled
		for one or more rulesets with the enable() or enable_tags() methods.
		The ast representation of the rule's condition is provided to allow
		the filter_ruleset object to parse the ast to obtain event types
		or do other analysis/indexing of the condition.
		\param rule The rule to be added
		\param the filter representing the rule's filtering condition.
		\param condition The AST representing the rule's filtering condition
	*/
	virtual void add(
		const falco_rule& rule,
		std::shared_ptr<sinsp_filter> filter,
		std::shared_ptr<libsinsp::filter::ast::expr> condition) = 0;

	/*!
		\brief Adds all rules contained in the provided
		rule_loader::compile_output struct. Only
		those rules with the provided source and those rules
		with priority >= min_priority should be added. The
		intent is that this replaces add(). However, we retain
		add() for backwards compatibility. Any rules added via
		add() are also added to this ruleset. The default
		implementation iterates over rules and calls add(),
		but can be overridden.
		\param rule The compile output.
		\param min_priority Only add rules with priority above this priority.
		\param source Only add rules with source equal to this source.
	*/
	virtual void add_compile_output(
		const rule_loader::compile_output& compile_output,
		falco_common::priority_type min_priority,
		const std::string& source)
	{
		for (const auto& rule : compile_output.rules)
		{
			if(rule.priority <= min_priority &&
			   rule.source == source)
			{
				add(rule, rule.filter, rule.condition);
			}
		}
	};

	/*!
		\brief Erases the internal state. All rules are disabled in each
		ruleset, and all the rules defined with add() are removed.
	*/
	virtual void clear() = 0;

	/*!
		\brief This is meant to be called after all rules have been added
		with add() and enabled on the given ruleset with enable()/enable_tags().
	*/
	virtual void on_loading_complete() = 0;

	/*!
		\brief Processes an event and tries to find a match in a given ruleset.
		\return true if a match is found, false otherwise
		\param evt The event to be processed
		\param match If true is returned, this is filled-out with the first rule
		that matched the event
		\param ruleset_id The id of the ruleset to be used
	*/
	virtual bool run(
		sinsp_evt *evt,
		falco_rule& match,
		uint16_t ruleset_id) = 0;
	
	/*!
		\brief Processes an event and tries to find a match in a given ruleset.
		\return true if a match is found, false otherwise
		\param evt The event to be processed
		\param matches If true is returned, this is filled-out with all the rules
		that matched the event
		\param ruleset_id The id of the ruleset to be used
	*/
	virtual bool run(
		sinsp_evt *evt,
		std::vector<falco_rule>& matches,
		uint16_t ruleset_id) = 0;

	/*!
		\brief Returns the number of rules enabled in a given ruleset
		\param ruleset_id The id of the ruleset to be used
	*/
	virtual uint64_t enabled_count(uint16_t ruleset_id) = 0;

	/*!
		\brief Returns the union of the evttypes of all the rules enabled
		in a given ruleset
		\param ruleset_id The id of the ruleset to be used
		\deprecated Must use the new typing-improved `enabled_event_codes`
		and `enabled_sc_codes` instead
		\note todo(jasondellaluce): remove this in future refactors
	*/
	virtual void enabled_evttypes(
		std::set<uint16_t> &evttypes,
		uint16_t ruleset) = 0;
	
	/*!
		\brief Returns the all the ppm_sc_codes matching the rules
		enabled in a given ruleset.
		\param ruleset_id The id of the ruleset to be used
	*/
	virtual libsinsp::events::set<ppm_sc_code> enabled_sc_codes(
		uint16_t ruleset) = 0;
	
	/*!
		\brief Returns the all the ppm_event_codes matching the rules
		enabled in a given ruleset.
		\param ruleset_id The id of the ruleset to be used
	*/
	virtual libsinsp::events::set<ppm_event_code> enabled_event_codes(
		uint16_t ruleset) = 0;

	/*!
		\brief Find those rules matching the provided substring and enable
		them in the provided ruleset.
		\param substring Substring used to match rule names.
		If empty, all rules are matched.
		\param match_exact If true, substring must be an exact match for a
		given rule name. Otherwise, any rules having substring as a substring
		in the rule name are enabled/disabled.
		\param ruleset_id The id of the ruleset to be used
	*/
	virtual void enable(
		const std::string &substring,
		bool match_exact,
		uint16_t ruleset_id) = 0;

	/*!
		\brief Find those rules matching the provided substring and disable
		them in the provided ruleset.
		\param substring Substring used to match rule names.
		If empty, all rules are matched.
		\param match_exact If true, substring must be an exact match for a
		given rule name. Otherwise, any rules having substring as a substring
		in the rule name are enabled/disabled.
		\param ruleset_id The id of the ruleset to be used
	*/
	virtual void disable(
		const std::string &substring,
		bool match_exact,
		uint16_t ruleset_id) = 0;

	/*!
		\brief Find those rules that have a tag in the set of tags and
		enable them for the provided ruleset. Note that the enabled
		status is on the rules, and not the tags--if a rule R has
		tags (a, b), and you call enable_tags([a]) and then
		disable_tags([b]), R will be disabled despite the
		fact it has tag a and was enabled by the first call to
		enable_tags.
		\param substring Tags used to match ruless
		\param ruleset_id The id of the ruleset to be used
	*/
	virtual void enable_tags(
		const std::set<std::string> &tags,
		uint16_t ruleset_id) = 0;

	/*!
		\brief Find those rules that have a tag in the set of tags and
		disable them for the provided ruleset. Note that the disabled
		status is on the rules, and not the tags--if a rule R has
		tags (a, b), and you call enable_tags([a]) and then
		disable_tags([b]), R will be disabled despite the
		fact it has tag a and was enabled by the first call to
		enable_tags.
		\param substring Tags used to match ruless
		\param ruleset_id The id of the ruleset to be used
	*/
	virtual void disable_tags(
		const std::set<std::string> &tags,
		uint16_t ruleset_id) = 0;

private:
	engine_state_funcs m_engine_state;
};

/*!
	\brief Represents a factory that creates filter_ruleset objects
*/
class filter_ruleset_factory
{
public:
	virtual ~filter_ruleset_factory() = default;

	virtual std::shared_ptr<filter_ruleset> new_ruleset() = 0;
};
