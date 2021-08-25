/*
Copyright (C) 2019 The Falco Authors.

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

#include <string>
#include <set>
#include <vector>
#include <list>
#include <map>

#include "sinsp.h"
#include "filter.h"
#include "event.h"

#include "gen_filter.h"

class falco_ruleset
{
public:
	falco_ruleset();
	virtual ~falco_ruleset();

	void add(std::string &name,
		 std::set<std::string> &tags,
		 std::shared_ptr<gen_event_filter> filter);

	// rulesets are arbitrary numbers and should be managed by the caller.
        // Note that rulesets are used to index into a std::vector so
        // specifying unnecessarily large rulesets will result in
        // unnecessarily large vectors.

	// Find those rules matching the provided substring and set
	// their enabled status to enabled. If match_exact is true,
	// substring must be an exact match for a given rule
	// name. Otherwise, any rules having substring as a substring
	// in the rule name are enabled/disabled.
	void enable(const std::string &substring, bool match_exact, bool enabled, uint16_t ruleset = 0);

	// Find those rules that have a tag in the set of tags and set
	// their enabled status to enabled. Note that the enabled
	// status is on the rules, and not the tags--if a rule R has
	// tags (a, b), and you call enable_tags([a], true) and then
	// enable_tags([b], false), R will be disabled despite the
	// fact it has tag a and was enabled by the first call to
	// enable_tags.
	void enable_tags(const std::set<std::string> &tags, bool enabled, uint16_t ruleset = 0);


	// Return the number of falco rules enabled for the provided ruleset
	uint64_t num_rules_for_ruleset(uint16_t ruleset = 0);

	// Match all filters against the provided event.
	bool run(gen_event *evt, uint16_t ruleset = 0);

	// Populate the provided set of event types used by this ruleset.
	void evttypes_for_ruleset(std::set<uint16_t> &evttypes, uint16_t ruleset);

private:

	class filter_wrapper {
	public:
		std::string name;
		std::set<std::string> tags;
		std::shared_ptr<gen_event_filter> filter;
	};

	typedef std::list<std::shared_ptr<filter_wrapper>> filter_wrapper_list;

	// A group of filters all having the same ruleset
	class ruleset_filters {
	public:
		ruleset_filters();

		virtual ~ruleset_filters();

		void add_filter(std::shared_ptr<filter_wrapper> wrap);
		void remove_filter(std::shared_ptr<filter_wrapper> wrap);

		uint64_t num_filters();

		bool run(gen_event *evt);

		void evttypes_for_ruleset(std::set<uint16_t> &evttypes);

	private:
		void add_wrapper_to_list(filter_wrapper_list &wrappers, std::shared_ptr<filter_wrapper> wrap);
		void remove_wrapper_from_list(filter_wrapper_list &wrappers, std::shared_ptr<filter_wrapper> wrap);

		// Vector indexes from event type to a set of filters. There can
		// be multiple filters for a given event type.
		// NOTE: This is used only when the event sub-type is 0.
		std::vector<filter_wrapper_list> m_filter_by_event_type;

		filter_wrapper_list m_filter_all_event_types;

		// All filters added. Used to make num_filters() fast.
		std::set<std::shared_ptr<filter_wrapper>> m_filters;
	};

	// Vector indexes from ruleset id to set of rules.
	std::vector<std::shared_ptr<ruleset_filters>> m_rulesets;

	// All filters added. The set of enabled filters is held in m_rulesets
	std::set<std::shared_ptr<filter_wrapper>> m_filters;
};
