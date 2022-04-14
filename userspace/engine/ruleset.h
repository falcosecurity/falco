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

#include "falco_rule.h"
#include <filter/ast.h>
#include <filter.h>
#include <event.h>
#include <gen_filter.h>

/*!
	\brief Represents a manager for rulesets.A ruleset represents a set of
	enabled rules that is able to process events and find potential rule
	matches. By convention, the ruleset with id = 0 is the default one.
*/
class filter_ruleset
{
public:
	virtual ~filter_ruleset() = default;

	/*!
		\brief Adds a rule and its filtering condition inside the manager.
		An exception is thrown is case of error. This method only adds the rule
		inside the internal collection, but does not enable it for any ruleset.
		The rule must be enabled for one or more rulesets with the enable() or
		enable_tags() methods.
		\param rule The rule to be added
		\param condition The AST representing the rule's filtering condition
	*/
	virtual void add(
		const falco_rule& rule,
		std::shared_ptr<libsinsp::filter::ast::expr> condition) = 0;
	
	/*!
		\brief Erases the internal state. All rules are disabled in each
		ruleset, and all the rules defined with add() are removed.
	*/
	virtual void clear() = 0;

	/*!
		\brief Returns the numeric id of a ruleset given its name.
		If a ruleset has been used before, its previously assigned id is
		returned. Otherwise, a new ruleset is created with the given name
		and a new id is assigned to it.
	*/
	virtual uint16_t ruleset_id(const std::string &name) = 0;

	/*!
		\brief Optimizes the structure of a given ruleset.
		This can be used by the different implementations to optimize the
		underlying data structures for better runtime performance and memory
		usage. This is meant to be called after all rules have been added with
		add() and enabled on the given ruleset with enable()/enable_tags().
		\param ruleset The id of the ruleset to be used
	*/
	virtual void optimize(uint16_t ruleset = 0) = 0;

	/*!
		\brief Processes an event and tries to find a match in a given ruleset.
		\return true if a match is found, false otherwise
		\param evt The event to be processed
		\param match If true is returned, this is filled-out with the rule
		that matched the event
		\param ruleset The id of the ruleset to be used
	*/
	virtual bool run(
		gen_event *evt,
		falco_rule& match,
		uint16_t ruleset = 0) = 0;
	
	/*!
		\brief Returns the number of rules enabled in a given ruleset
		\param ruleset The id of the ruleset to be used
	*/
	virtual uint64_t enabled_count(uint16_t ruleset = 0) = 0;

	/*!
		\brief Returns the union of the evttypes of all the rules enabled
		in a given ruleset
		\param ruleset The id of the ruleset to be used
	*/
	virtual void enabled_evttypes(
		std::set<uint16_t> &evttypes,
		uint16_t ruleset) = 0;

	/*!
		\brief Find those rules matching the provided substring and set
		their enabled status to enabled in a given ruleset.
		\param substring Substring used to match rule names.
		If empty, all rules are matched.
		\param match_exact If true, substring must be an exact match for a
		given rule name. Otherwise, any rules having substring as a substring
		in the rule name are enabled/disabled.
		\param enabled The enabled status to set on all matching rules
		\param ruleset The id of the ruleset to be used
	*/
	virtual void enable(
		const std::string &substring,
		bool match_exact,
		bool enabled,
		uint16_t ruleset = 0) = 0;

	/*!
		\brief Find those rules that have a tag in the set of tags and
		set their enabled status to enabled. Note that the enabled
		status is on the rules, and not the tags--if a rule R has
		tags (a, b), and you call enable_tags([a], true) and then
		enable_tags([b], false), R will be disabled despite the
		fact it has tag a and was enabled by the first call to
		enable_tags.
		\param substring Tags used to match ruless
		\param enabled The enabled status to set on all matching rules
		\param ruleset The id of the ruleset to be used
	*/
	virtual void enable_tags(
		const std::set<std::string> &tags,
		bool enabled,
		uint16_t ruleset = 0) = 0;
};

/*!
	\brief Represents a factory that creates filter_ruleset objects
*/
class filter_ruleset_factory
{
public:
	virtual std::shared_ptr<filter_ruleset> new_ruleset() = 0;
};
