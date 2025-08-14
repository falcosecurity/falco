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

#include "indexable_ruleset.h"

#include <string>
#include <set>
#include <vector>

/*!
    \brief A filter_ruleset that indexes enabled rules by event type,
    and performs linear search on each event type bucket
*/

struct evttype_index_wrapper {
	const std::string &name() { return m_rule.name; }
	const std::set<std::string> &tags() { return m_rule.tags; }
	const libsinsp::events::set<ppm_sc_code> &sc_codes() { return m_sc_codes; }
	const libsinsp::events::set<ppm_event_code> &event_codes() { return m_event_codes; }

	falco_rule m_rule;
	libsinsp::events::set<ppm_sc_code> m_sc_codes;
	libsinsp::events::set<ppm_event_code> m_event_codes;
	std::shared_ptr<sinsp_filter> m_filter;
};

class evttype_index_ruleset : public indexable_ruleset<evttype_index_wrapper> {
public:
	explicit evttype_index_ruleset(std::shared_ptr<sinsp_filter_factory> factory);
	virtual ~evttype_index_ruleset() override;

	// From filter_ruleset
	void add(const falco_rule &rule,
	         std::shared_ptr<sinsp_filter> filter,
	         std::shared_ptr<libsinsp::filter::ast::expr> condition) override;

	void on_loading_complete() override;

	// From indexable_ruleset
	bool run_wrappers(sinsp_evt *evt,
	                  filter_wrapper_list &wrappers,
	                  uint16_t ruleset_id,
	                  falco_rule &match) override;
	bool run_wrappers(sinsp_evt *evt,
	                  filter_wrapper_list &wrappers,
	                  uint16_t ruleset_id,
	                  std::vector<falco_rule> &matches) override;

	// Print each enabled rule when running Falco with falco logger
	// log_level=debug; invoked within on_loading_complete()
	void print_enabled_rules_falco_logger();

private:
	std::shared_ptr<sinsp_filter_factory> m_filter_factory;
};

class evttype_index_ruleset_factory : public filter_ruleset_factory {
public:
	inline explicit evttype_index_ruleset_factory(std::shared_ptr<sinsp_filter_factory> factory):
	        m_filter_factory(factory) {}

	inline std::shared_ptr<filter_ruleset> new_ruleset() override {
		return std::make_shared<evttype_index_ruleset>(m_filter_factory);
	}

private:
	std::shared_ptr<sinsp_filter_factory> m_filter_factory;
};
