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

// Gen filtering TODO
//  - DONE Clean up use/sharing of factories amongst engine-related classes.
//  - DONE Fix outputs to actually use factories
//  - Review gen_filter apis to see if they have only the required interfaces
//  - Fix json filterchecks to split json and evt.time filterchecks.

#pragma once

#include <string>
#include <memory>
#include <set>

#include <nlohmann/json.hpp>

#include "sinsp.h"
#include "filter.h"

#include "json_evt.h"
#include "rules.h"
#include "ruleset.h"

#include "config_falco_engine.h"
#include "falco_common.h"

extern "C"
{
#include "hawk.h"
}

//
// This class acts as the primary interface between a program and the
// falco rules engine. Falco outputs (writing to files/syslog/etc) are
// handled in a separate class falco_outputs.
//

class falco_engine : public falco_common
{
public:
	falco_engine(bool seed_rng = true, const std::string &alternate_lua_dir = FALCO_ENGINE_SOURCE_LUA_DIR);
	virtual ~falco_engine();

	falco_engine(const falco_engine &rhs);
	falco_engine *clone();

	// A given engine has a version which identifies the fields
	// and rules file format it supports. This version will change
	// any time the code that handles rules files, expression
	// fields, etc, changes.
	static uint32_t engine_version();

	// Print to stdout (using printf) a description of each field supported by this engine.
	void list_fields(bool names_only = false);

	//
	// Load rules either directly or from a filename.
	//
	void load_rules_file(const std::string &rules_filename, bool verbose, bool all_events);
	void load_rules(const std::string &rules_content, bool verbose, bool all_events);

	// Watch and live-reload rules using an external ABI interface provided by libhawk
	void watch_rules(bool verbose, bool all_events);

	//
	// Enable/Disable any rules matching the provided substring.
	// If the substring is "", all rules are enabled/disabled.
	// When provided, enable/disable these rules in the
	// context of the provided ruleset. The ruleset (id) can later
	// be passed as an argument to process_event(). This allows
	// for different sets of rules being active at once.
	//
	void enable_rule(const std::string &substring, bool enabled, const std::string &ruleset);

	// Wrapper that assumes the default ruleset
	void enable_rule(const std::string &substring, bool enabled);

	// Like enable_rule, but the rule name must be an exact match.
	void enable_rule_exact(const std::string &rule_name, bool enabled, const std::string &ruleset);

	// Wrapper that assumes the default ruleset
	void enable_rule_exact(const std::string &rule_name, bool enabled);

	//
	// Enable/Disable any rules with any of the provided tags (set, exact matches only)
	//
	void enable_rule_by_tag(const std::set<std::string> &tags, bool enabled, const std::string &ruleset);

	// Wrapper that assumes the default ruleset
	void enable_rule_by_tag(const std::set<std::string> &tags, bool enabled);

	// Only load rules having this priority or more severe.
	void set_min_priority(falco_common::priority_type priority);

	//
	// Return the ruleset id corresponding to this ruleset name,
	// creating a new one if necessary. If you provide any ruleset
	// to enable_rule/enable_rule_by_tag(), you should look up the
	// ruleset id and pass it to process_event().
	//
	uint16_t find_ruleset_id(const std::string &ruleset);

	//
	// Return the number of falco rules enabled for the provided ruleset
	//
	uint64_t num_rules_for_ruleset(const std::string &ruleset);

	//
	// Print details on the given rule. If rule is NULL, print
	// details on all rules.
	//
	void describe_rule(std::string *rule);

	//
	// Print statistics on how many events matched each rule.
	//
	void print_stats();

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

	// **Methods Related to k8s audit log events, which are
	// **represented as json objects.
	struct rule_result
	{
		gen_event *evt;
		std::string rule;
		std::string source;
		falco_common::priority_type priority_num;
		std::string format;
	};

	//
	// Given a raw json object, return a list of k8s audit event
	// objects that represent the object. This method handles
	// things such as EventList splitting.
	//
	// Returns true if the json object was recognized as a k8s
	// audit event(s), false otherwise.
	//
	bool parse_k8s_audit_json(nlohmann::json &j, std::list<json_event> &evts, bool top = true);

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
	std::unique_ptr<rule_result> process_k8s_audit_event(json_event *ev, uint16_t ruleset_id);

	//
	// Wrapper assuming the default ruleset
	//
	std::unique_ptr<rule_result> process_k8s_audit_event(json_event *ev);

	//
	// Add a k8s_audit filter to the engine
	//
	void add_k8s_audit_filter(std::string &rule,
				  std::set<std::string> &tags,
				  json_event_filter *filter);

	// **Methods Related to Sinsp Events e.g system calls
	//
	// Given a ruleset, fill in a bitset containing the event
	// types for which this ruleset can run.
	//
	void evttypes_for_ruleset(std::vector<bool> &evttypes, const std::string &ruleset);

	//
	// Given a ruleset, fill in a bitset containing the syscalls
	// for which this ruleset can run.
	//
	void syscalls_for_ruleset(std::vector<bool> &syscalls, const std::string &ruleset);

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
	std::unique_ptr<rule_result> process_sinsp_event(sinsp_evt *ev, uint16_t ruleset_id);

	//
	// Wrapper assuming the default ruleset
	//
	std::unique_ptr<rule_result> process_sinsp_event(sinsp_evt *ev);

	//
	// Add a filter, which is related to the specified set of
	// event types/syscalls, to the engine.
	//
	void add_sinsp_filter(std::string &rule,
			      std::set<uint32_t> &evttypes,
			      std::set<uint32_t> &syscalls,
			      std::set<std::string> &tags,
			      sinsp_filter *filter);

	sinsp_filter_factory &sinsp_factory();
	json_event_filter_factory &json_factory();

	bool is_ready();

private:
	static nlohmann::json::json_pointer k8s_audit_time;

	//
	// Determine whether the given event should be matched at all
	// against the set of rules, given the current sampling
	// ratio/multiplier.
	//
	inline bool should_drop_evt();
	shared_ptr<sinsp_filter_factory> m_sinsp_factory;
	shared_ptr<json_event_filter_factory> m_json_factory;

	falco_rules *m_rules;
	uint16_t m_next_ruleset_id;
	std::map<string, uint16_t> m_known_rulesets;
	falco_common::priority_type m_min_priority;

	std::unique_ptr<falco_sinsp_ruleset> m_sinsp_rules;
	std::unique_ptr<falco_ruleset> m_k8s_audit_rules;

	std::string m_alternate_lua_dir;

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

	bool m_is_ready = false;
};
