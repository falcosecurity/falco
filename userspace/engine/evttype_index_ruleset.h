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

#include "filter_ruleset.h"
#include "sinsp.h"
#include "filter.h"
#include "event.h"

#include "gen_filter.h"

/*!
	\brief A filter_ruleset that indexes enabled rules by event type,
	and performs linear search on each event type bucket
*/
class evttype_index_ruleset: public filter_ruleset
{
public:
	evttype_index_ruleset(std::shared_ptr<gen_event_filter_factory> factory);
	virtual ~evttype_index_ruleset();

	void add(
		const falco_rule& rule,
		std::shared_ptr<gen_event_filter> filter,
		std::shared_ptr<libsinsp::filter::ast::expr> condition) override;

	void clear() override;

	bool run(gen_event *evt, falco_rule& match, uint16_t rulset_id);

	uint64_t enabled_count(uint16_t ruleset_id) override;

	void on_loading_complete() override;

	void enable(
		const std::string &substring,
		bool match_exact,
		uint16_t rulset_id) override;

	void disable(
		const std::string &substring,
		bool match_exact,
		uint16_t rulset_id) override;

	void enable_tags(
		const std::set<std::string> &tags,
		uint16_t rulset_id) override;

	void disable_tags(
		const std::set<std::string> &tags,
		uint16_t rulset_id) override;

	// evttypes for a ruleset
	void enabled_evttypes(
		std::set<uint16_t> &evttypes,
		uint16_t ruleset) override;

private:

	// Helper used by enable()/disable()
	void enable_disable(
		const std::string &substring,
		bool match_exact,
		bool enabled,
		uint16_t rulset_id);

	// Helper used by enable_tags()/disable_tags()
	void enable_disable_tags(
		const std::set<std::string> &tags,
		bool enabled,
		uint16_t rulset_id);

	struct filter_wrapper
	{
		falco_rule rule;
		libsinsp::events::set<ppm_event_code> evttypes;
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

		bool run(gen_event *evt, falco_rule& match);

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

	std::shared_ptr<gen_event_filter_factory> m_filter_factory;
	std::vector<std::string> m_ruleset_names;
};

class evttype_index_ruleset_factory: public filter_ruleset_factory
{
public:
	inline evttype_index_ruleset_factory(
		std::shared_ptr<gen_event_filter_factory> factory
	): m_filter_factory(factory) { }

	inline std::shared_ptr<filter_ruleset> new_ruleset() override
	{
		std::shared_ptr<filter_ruleset> ret(
			new evttype_index_ruleset(m_filter_factory));
		return ret;
	}

private:
	std::shared_ptr<gen_event_filter_factory> m_filter_factory;
};
