/*
Copyright (C) 2016 Draios inc.

This file is part of falco.

falco is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

falco is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with falco.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <string>
#include <memory>
#include <set>

#include "sinsp.h"
#include "filter.h"

#include "rules.h"

#include "falco_common.h"

//
// This class acts as the primary interface between a program and the
// falco rules engine. Falco outputs (writing to files/syslog/etc) are
// handled in a separate class falco_outputs.
//

class falco_engine : public falco_common
{
public:
	falco_engine(bool seed_rng=true);
	virtual ~falco_engine();

	//
	// Load rules either directly or from a filename.
	//
	void load_rules_file(const std::string &rules_filename, bool verbose, bool all_events);
	void load_rules(const std::string &rules_content, bool verbose, bool all_events);

	//
	// Enable/Disable any rules matching the provided pattern
	// (regex). When provided, enable/disable these rules in the
	// context of the provided ruleset. The ruleset (id) can later
	// be passed as an argument to process_event(). This allows
	// for different sets of rules being active at once.
	//
	void enable_rule(const std::string &pattern, bool enabled, const std::string &ruleset);

	// Wrapper that assumes the default ruleset
	void enable_rule(const std::string &pattern, bool enabled);

	//
	// Enable/Disable any rules with any of the provided tags (set, exact matches only)
	//
	void enable_rule_by_tag(const std::set<std::string> &tags, bool enabled, const std::string &ruleset);

	// Wrapper that assumes the default ruleset
	void enable_rule_by_tag(const std::set<std::string> &tags, bool enabled);

	// Only load rules having this priority or more severe.
	void set_min_priority(falco_common::priority_type priority);

	struct rule_result {
		sinsp_evt *evt;
		std::string rule;
		falco_common::priority_type priority_num;
		std::string format;
	};

	//
	// Return the ruleset id corresponding to this ruleset name,
	// creating a new one if necessary. If you provide any ruleset
	// to enable_rule/enable_rule_by_tag(), you should look up the
	// ruleset id and pass it to process_event().
	//
	uint16_t find_ruleset_id(const std::string &ruleset);

	//
	// Given an event, check it against the set of rules in the
	// engine and if a matching rule is found, return details on
	// the rule that matched. If no rule matched, returns NULL.
	//
	// When ruleset_id is provided, use the enabled/disabled status
	// associated with the provided ruleset. This is only useful
	// when you have previously called enable_rule/enable_rule_by_tag
	// with a ruleset string.
	//
	// the returned rule_result is allocated and must be delete()d.
	std::unique_ptr<rule_result> process_event(sinsp_evt *ev, uint16_t ruleset_id);

	//
	// Wrapper assuming the default ruleset
	//
	std::unique_ptr<rule_result> process_event(sinsp_evt *ev);

	//
	// Print details on the given rule. If rule is NULL, print
	// details on all rules.
	//
	void describe_rule(std::string *rule);

	//
	// Print statistics on how many events matched each rule.
	//
	void print_stats();

	//
	// Add a filter, which is related to the specified set of
	// event types, to the engine.
	//
	void add_evttype_filter(std::string &rule,
				std::set<uint32_t> &evttypes,
				std::set<std::string> &tags,
				sinsp_filter* filter);

	// Clear all existing filters.
	void clear_filters();

	//
	// Set the sampling ratio, which can affect which events are
	// matched against the set of rules.
	//
	void set_sampling_ratio(uint32_t sampling_ratio);

	//
	// Set the sampling ratio multiplier, which can affect which
	// events are matched against the set of rules.
	//
	void set_sampling_multiplier(double sampling_multiplier);

	//
	// You can optionally add "extra" formatting fields to the end
	// of all output expressions. You can also choose to replace
	// %container.info with the extra information or add it to the
	// end of the expression. This is used in open source falco to
	// add k8s/mesos/container information to outputs when
	// available.
	//
	void set_extra(string &extra, bool replace_container_info);

private:

	//
	// Determine whether the given event should be matched at all
	// against the set of rules, given the current sampling
	// ratio/multiplier.
	//
	inline bool should_drop_evt();

	falco_rules *m_rules;
	uint16_t m_next_ruleset_id;
	std::map<string, uint16_t> m_known_rulesets;
	std::unique_ptr<sinsp_evttype_filter> m_evttype_filter;
	falco_common::priority_type m_min_priority;

	//
	// Here's how the sampling ratio and multiplier influence
	// whether or not an event is dropped in
	// should_drop_evt(). The intent is that m_sampling_ratio is
	// generally changing external to the engine e.g. in the main
	// inspector class based on how busy the inspector is. A
	// sampling ratio implies no dropping. Values > 1 imply
	// increasing levels of dropping. External to the engine, the
	// sampling ratio results in events being dropped at the
	// kernel/inspector interface.
	//
	// The sampling multiplier is an amplification to the sampling
	// factor in m_sampling_ratio. If 0, no additional events are
	// dropped other than those that might be dropped by the
	// kernel/inspector interface. If 1, events that make it past
	// the kernel module are subject to an additional level of
	// dropping at the falco engine, scaling with the sampling
	// ratio in m_sampling_ratio.
	//

	uint32_t m_sampling_ratio;
	double m_sampling_multiplier;

	std::string m_lua_main_filename = "rule_loader.lua";
	std::string m_default_ruleset = "falco-default-ruleset";
	uint32_t m_default_ruleset_id;

	std::string m_extra;
	bool m_replace_container_info;
};

