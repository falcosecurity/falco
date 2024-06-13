// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

/* This describes the interface for an "indexable" ruleset, that is, a
 * ruleset that can enable/disable abstract filters for various
 * ruleset ids.
 *
 * It's used by evttype_index_ruleset as well as other rulesets that
 * need the same functionality but don't want to copy the same code.
 */

#pragma once

#include "filter_ruleset.h"

#include <libsinsp/sinsp.h>
#include <libsinsp/filter.h>
#include <libsinsp/event.h>

#include <functional>
#include <memory>
#include <string>

class indexable_ruleset : public filter_ruleset
{
public:
	indexable_ruleset() = default;
	virtual ~indexable_ruleset() = default;

	// Required to implement filter_ruleset
	void clear() override;

	uint64_t enabled_count(uint16_t ruleset_id) override;

	void enabled_evttypes(
		std::set<uint16_t> &evttypes,
		uint16_t ruleset) override;

	libsinsp::events::set<ppm_sc_code> enabled_sc_codes(
		uint16_t ruleset) override;

	libsinsp::events::set<ppm_event_code> enabled_event_codes(
		uint16_t ruleset) override;

	void enable(
		const std::string &pattern,
		match_type match,
		uint16_t ruleset_id) override;

	void disable(
		const std::string &pattern,
		match_type match,
		uint16_t ruleset_id) override;

	void enable_tags(
		const std::set<std::string> &tags,
		uint16_t ruleset_id) override;

	void disable_tags(
		const std::set<std::string> &tags,
		uint16_t ruleset_id) override;

	// Note that subclasses do *not* implement run. Instead, they
	// implement run_wrappers.
	bool run(sinsp_evt *evt, falco_rule &match, uint16_t ruleset_id) override;
	bool run(sinsp_evt *evt, std::vector<falco_rule> &matches, uint16_t ruleset_id) override;

	// Methods for working with filter wrappers

	// A derived class should add "filter wrappers" that implement
	// these methods. They return the necessary information
	// required to segregate filters by name, tags, and event
	// types.
	struct filter_wrapper
	{
		virtual const std::string &name() = 0;
		virtual const std::set<std::string> &tags() = 0;
		virtual const libsinsp::events::set<ppm_sc_code> &sc_codes() = 0;
		virtual const libsinsp::events::set<ppm_event_code> &event_codes() = 0;
	};

	typedef std::list<std::shared_ptr<filter_wrapper>>
		filter_wrapper_list;

	// Subclasses should call add_wrapper (most likely from
	// filter_ruleset::add or ::add_compile_output) to add filters.
	void add_wrapper(std::shared_ptr<filter_wrapper> wrap);

	// If a subclass needs to iterate over all filters, they can
	// call iterate with this function, which will be called for
	// all filters.
	typedef std::function<void(const std::shared_ptr<filter_wrapper> &wrap)> filter_wrapper_func;
	uint64_t iterate(filter_wrapper_func func);

	// A subclass must implement these methods. They are analogous
	// to run() but take care of selecting filters that match a
	// ruleset and possibly an event type.
	virtual bool run_wrappers(sinsp_evt *evt, filter_wrapper_list &wrappers, uint16_t ruleset_id, std::vector<falco_rule> &matches) = 0;
	virtual bool run_wrappers(sinsp_evt *evt, filter_wrapper_list &wrappers, uint16_t ruleset_id, falco_rule &match) = 0;

private:
	// Helper used by enable()/disable()
	void enable_disable(
		const std::string &pattern,
		match_type match,
		bool enabled,
		uint16_t ruleset_id);

	// Helper used by enable_tags()/disable_tags()
	void enable_disable_tags(
		const std::set<std::string> &tags,
		bool enabled,
		uint16_t ruleset_id);

	// A group of filters all having the same ruleset
	class ruleset_filters
	{
	public:
		ruleset_filters(uint16_t ruleset_id):
			m_ruleset_id(ruleset_id) {}

		virtual ~ruleset_filters(){};

		void add_filter(std::shared_ptr<filter_wrapper> wrap);
		void remove_filter(std::shared_ptr<filter_wrapper> wrap);

		uint64_t num_filters();

		inline const std::set<std::shared_ptr<filter_wrapper>> &get_filters() const
		{
			return m_filters;
		}

		// Evaluate an event against the ruleset and return the first rule
		// that matched.
		bool run(indexable_ruleset &ruleset, sinsp_evt *evt, falco_rule &match);

		//  Evaluate an event against the ruleset and return all the
		//	matching rules.
		bool run(indexable_ruleset &ruleset, sinsp_evt *evt, std::vector<falco_rule> &matches);

		libsinsp::events::set<ppm_sc_code> sc_codes();

		libsinsp::events::set<ppm_event_code> event_codes();

	private:
		void add_wrapper_to_list(filter_wrapper_list &wrappers, std::shared_ptr<filter_wrapper> wrap);
		void remove_wrapper_from_list(filter_wrapper_list &wrappers, std::shared_ptr<filter_wrapper> wrap);

		uint16_t m_ruleset_id;

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
