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

#include "evttype_index_ruleset.h"

#include "logger.h"

#include <algorithm>

evttype_index_ruleset::evttype_index_ruleset(std::shared_ptr<sinsp_filter_factory> f):
        m_filter_factory(f) {}

evttype_index_ruleset::~evttype_index_ruleset() {}

void evttype_index_ruleset::add(const falco_rule &rule,
                                std::shared_ptr<sinsp_filter> filter,
                                std::shared_ptr<libsinsp::filter::ast::expr> condition) {
	try {
		auto wrap = std::make_shared<evttype_index_wrapper>();
		wrap->m_rule = rule;
		wrap->m_filter = filter;
		if(rule.source == falco_common::syscall_source) {
			wrap->m_sc_codes = libsinsp::filter::ast::ppm_sc_codes(condition.get());
			wrap->m_event_codes = libsinsp::filter::ast::ppm_event_codes(condition.get());
		} else {
			wrap->m_sc_codes = {};
			wrap->m_event_codes = {ppm_event_code::PPME_PLUGINEVENT_E};
		}
		wrap->m_event_codes.insert(ppm_event_code::PPME_ASYNCEVENT_E);

		add_wrapper(wrap);
	} catch(const sinsp_exception &e) {
		throw falco_exception(std::string(e.what()));
	}
}

void evttype_index_ruleset::on_loading_complete() {
	print_enabled_rules_falco_logger();
}

bool evttype_index_ruleset::run_wrappers(sinsp_evt *evt,
                                         filter_wrapper_list &wrappers,
                                         uint16_t ruleset_id,
                                         falco_rule &match) {
	for(const auto &wrap : wrappers) {
		if(wrap->m_filter->run(evt)) {
			match = wrap->m_rule;
			return true;
		}
	}

	return false;
}

bool evttype_index_ruleset::run_wrappers(sinsp_evt *evt,
                                         filter_wrapper_list &wrappers,
                                         uint16_t ruleset_id,
                                         std::vector<falco_rule> &matches) {
	bool match_found = false;

	for(const auto &wrap : wrappers) {
		if(wrap->m_filter->run(evt)) {
			matches.push_back(wrap->m_rule);
			match_found = true;
		}
	}

	return match_found;
}

void evttype_index_ruleset::print_enabled_rules_falco_logger() {
	falco_logger::log(falco_logger::level::DEBUG, "Enabled rules:\n");

	auto logger = [](std::shared_ptr<evttype_index_wrapper> wrap) {
		falco_logger::log(falco_logger::level::DEBUG, std::string("   ") + wrap->name() + "\n");
	};

	uint64_t num_filters = iterate(logger);

	falco_logger::log(falco_logger::level::DEBUG,
	                  "(" + std::to_string(num_filters) + ") enabled rules in total\n");
}
