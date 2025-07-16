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

#include "falco_utils.h"
#include "filter_ruleset.h"

#include <libsinsp/sinsp.h>
#include <libsinsp/filter.h>
#include <libsinsp/event.h>

#include <functional>
#include <memory>
#include <string>

// A filter_wrapper should implement these methods:
//   const std::string &filter_wrapper::name();
//   const std::set<std::string> &filter_wrapper::tags();
//   const libsinsp::events::set<ppm_sc_code> &filter_wrapper::sc_codes();
//   const libsinsp::events::set<ppm_event_code> &filter_wrapper::event_codes();

template<class filter_wrapper>
class indexable_ruleset : public filter_ruleset {
public:
	indexable_ruleset() = default;
	virtual ~indexable_ruleset() override = default;

	// Required to implement filter_ruleset
	void clear() override {
		for(size_t i = 0; i < m_rulesets.size(); i++) {
			m_rulesets[i] = std::make_shared<ruleset_filters>(i);
		}
		m_filters.clear();
	}

	uint64_t enabled_count(uint16_t ruleset_id) override {
		while(m_rulesets.size() < (size_t)ruleset_id + 1) {
			m_rulesets.emplace_back(std::make_shared<ruleset_filters>(m_rulesets.size()));
		}

		return m_rulesets[ruleset_id]->num_filters();
	}

	void enabled_evttypes(std::set<uint16_t> &evttypes, uint16_t ruleset_id) override {
		evttypes.clear();
		for(const auto &e : enabled_event_codes(ruleset_id)) {
			evttypes.insert((uint16_t)e);
		}
	}

	libsinsp::events::set<ppm_sc_code> enabled_sc_codes(uint16_t ruleset_id) override {
		if(m_rulesets.size() < (size_t)ruleset_id + 1) {
			return {};
		}
		return m_rulesets[ruleset_id]->sc_codes();
	}

	libsinsp::events::set<ppm_event_code> enabled_event_codes(uint16_t ruleset_id) override {
		if(m_rulesets.size() < (size_t)ruleset_id + 1) {
			return {};
		}
		return m_rulesets[ruleset_id]->event_codes();
	}

	virtual void enable(const std::string &pattern,
	                    match_type match,
	                    uint16_t ruleset_id) override {
		enable_disable(pattern, match, true, ruleset_id);
	}

	virtual void disable(const std::string &pattern,
	                     match_type match,
	                     uint16_t ruleset_id) override {
		enable_disable(pattern, match, false, ruleset_id);
	}

	void enable_tags(const std::set<std::string> &tags, uint16_t ruleset_id) override {
		enable_disable_tags(tags, true, ruleset_id);
	}

	void disable_tags(const std::set<std::string> &tags, uint16_t ruleset_id) override {
		enable_disable_tags(tags, false, ruleset_id);
	}

	// Note that subclasses do *not* implement run. Instead, they
	// implement run_wrappers.
	bool run(sinsp_evt *evt, falco_rule &match, uint16_t ruleset_id) override {
		if(m_rulesets.size() < (size_t)ruleset_id + 1) {
			return false;
		}

		return m_rulesets[ruleset_id]->run(*this, evt, match);
	}

	bool run(sinsp_evt *evt, std::vector<falco_rule> &matches, uint16_t ruleset_id) override {
		if(m_rulesets.size() < (size_t)ruleset_id + 1) {
			return false;
		}

		return m_rulesets[ruleset_id]->run(*this, evt, matches);
	}

	typedef std::list<std::shared_ptr<filter_wrapper>> filter_wrapper_list;

	// Subclasses should call add_wrapper (most likely from
	// filter_ruleset::add or ::add_compile_output) to add filters.
	void add_wrapper(std::shared_ptr<filter_wrapper> wrap) { m_filters.insert(wrap); }

	// If a subclass needs to iterate over all filters, they can
	// call iterate with this function, which will be called for
	// all filters.
	typedef std::function<void(const std::shared_ptr<filter_wrapper> &wrap)> filter_wrapper_func;
	uint64_t iterate(filter_wrapper_func func) {
		uint64_t num_filters = 0;

		for(const auto &ruleset_ptr : m_rulesets) {
			if(ruleset_ptr) {
				for(const auto &wrap : ruleset_ptr->get_filters()) {
					num_filters++;
					func(wrap);
				}
			}
		}

		return num_filters;
	}

	// A subclass must implement these methods. They are analogous
	// to run() but take care of selecting filters that match a
	// ruleset and possibly an event type.
	virtual bool run_wrappers(sinsp_evt *evt,
	                          filter_wrapper_list &wrappers,
	                          uint16_t ruleset_id,
	                          std::vector<falco_rule> &matches) = 0;
	virtual bool run_wrappers(sinsp_evt *evt,
	                          filter_wrapper_list &wrappers,
	                          uint16_t ruleset_id,
	                          falco_rule &match) = 0;

private:
	// Helper used by enable()/disable()
	void enable_disable(const std::string &pattern,
	                    match_type match,
	                    bool enabled,
	                    uint16_t ruleset_id) {
		while(m_rulesets.size() < (size_t)ruleset_id + 1) {
			m_rulesets.emplace_back(std::make_shared<ruleset_filters>(m_rulesets.size()));
		}

		for(const auto &wrap : m_filters) {
			bool matches;
			std::string::size_type pos;

			switch(match) {
			case match_type::exact:
				pos = wrap->name().find(pattern);

				matches = (pattern == "" || (pos == 0 && pattern.size() == wrap->name().size()));
				break;
			case match_type::substring:
				matches = (pattern == "" || (wrap->name().find(pattern) != std::string::npos));
				break;
			case match_type::wildcard:
				matches = falco::utils::matches_wildcard(pattern, wrap->name());
				break;
			default:
				// should never happen
				matches = false;
			}

			if(matches) {
				if(enabled) {
					m_rulesets[ruleset_id]->add_filter(wrap);
				} else {
					m_rulesets[ruleset_id]->remove_filter(wrap);
				}
			}
		}
	}

	// Helper used by enable_tags()/disable_tags()
	void enable_disable_tags(const std::set<std::string> &tags, bool enabled, uint16_t ruleset_id) {
		while(m_rulesets.size() < (size_t)ruleset_id + 1) {
			m_rulesets.emplace_back(std::make_shared<ruleset_filters>(m_rulesets.size()));
		}

		for(const auto &wrap : m_filters) {
			std::set<std::string> intersect;

			set_intersection(tags.begin(),
			                 tags.end(),
			                 wrap->tags().begin(),
			                 wrap->tags().end(),
			                 inserter(intersect, intersect.begin()));

			if(!intersect.empty()) {
				if(enabled) {
					m_rulesets[ruleset_id]->add_filter(wrap);
				} else {
					m_rulesets[ruleset_id]->remove_filter(wrap);
				}
			}
		}
	}

	// A group of filters all having the same ruleset
	class ruleset_filters {
	public:
		explicit ruleset_filters(uint16_t ruleset_id): m_ruleset_id(ruleset_id) {}

		virtual ~ruleset_filters() {};

		void add_filter(std::shared_ptr<filter_wrapper> wrap) {
			if(wrap->event_codes().empty()) {
				// Should run for all event types
				add_wrapper_to_list(m_filter_all_event_types, wrap);
			} else {
				for(auto &etype : wrap->event_codes()) {
					if(m_filter_by_event_type.size() <= etype) {
						m_filter_by_event_type.resize(etype + 1);
					}

					add_wrapper_to_list(m_filter_by_event_type[etype], wrap);
				}
			}

			m_filters.insert(wrap);
		}

		void remove_filter(std::shared_ptr<filter_wrapper> wrap) {
			if(wrap->event_codes().empty()) {
				remove_wrapper_from_list(m_filter_all_event_types, wrap);
			} else {
				for(auto &etype : wrap->event_codes()) {
					if(etype < m_filter_by_event_type.size()) {
						remove_wrapper_from_list(m_filter_by_event_type[etype], wrap);
					}
				}
			}

			m_filters.erase(wrap);
		}

		uint64_t num_filters() { return m_filters.size(); }

		inline const std::set<std::shared_ptr<filter_wrapper>> &get_filters() const {
			return m_filters;
		}

		// Evaluate an event against the ruleset and return the first rule
		// that matched.
		bool run(indexable_ruleset &ruleset, sinsp_evt *evt, falco_rule &match) {
			if(evt->get_type() < m_filter_by_event_type.size() &&
			   m_filter_by_event_type[evt->get_type()].size() > 0) {
				if(ruleset.run_wrappers(evt,
				                        m_filter_by_event_type[evt->get_type()],
				                        m_ruleset_id,
				                        match)) {
					return true;
				}
			}

			// Finally, try filters that are not specific to an event type.
			if(m_filter_all_event_types.size() > 0) {
				if(ruleset.run_wrappers(evt, m_filter_all_event_types, m_ruleset_id, match)) {
					return true;
				}
			}

			return false;
		}

		//  Evaluate an event against the ruleset and return all the
		//  matching rules.
		bool run(indexable_ruleset &ruleset, sinsp_evt *evt, std::vector<falco_rule> &matches) {
			if(evt->get_type() < m_filter_by_event_type.size() &&
			   m_filter_by_event_type[evt->get_type()].size() > 0) {
				if(ruleset.run_wrappers(evt,
				                        m_filter_by_event_type[evt->get_type()],
				                        m_ruleset_id,
				                        matches)) {
					return true;
				}
			}

			// Finally, try filters that are not specific to an event type.
			if(m_filter_all_event_types.size() > 0) {
				if(ruleset.run_wrappers(evt, m_filter_all_event_types, m_ruleset_id, matches)) {
					return true;
				}
			}

			return false;
		}

		libsinsp::events::set<ppm_sc_code> sc_codes() {
			libsinsp::events::set<ppm_sc_code> res;
			for(const auto &wrap : m_filters) {
				res.insert(wrap->sc_codes().begin(), wrap->sc_codes().end());
			}
			return res;
		}
		libsinsp::events::set<ppm_event_code> event_codes() {
			libsinsp::events::set<ppm_event_code> res;
			for(const auto &wrap : m_filters) {
				res.insert(wrap->event_codes().begin(), wrap->event_codes().end());
			}
			return res;
		}

	private:
		void add_wrapper_to_list(filter_wrapper_list &wrappers,
		                         std::shared_ptr<filter_wrapper> wrap) {
			// This is O(n) but it's also uncommon
			// (when loading rules only).
			auto pos = std::find(wrappers.begin(), wrappers.end(), wrap);

			if(pos == wrappers.end()) {
				wrappers.push_back(wrap);
			}
		}

		void remove_wrapper_from_list(filter_wrapper_list &wrappers,
		                              std::shared_ptr<filter_wrapper> wrap) {
			// This is O(n) but it's also uncommon
			// (when loading rules only).
			auto pos = std::find(wrappers.begin(), wrappers.end(), wrap);
			if(pos != wrappers.end()) {
				wrappers.erase(pos);
			}
		}
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
