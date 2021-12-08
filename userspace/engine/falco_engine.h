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

#include "gen_filter.h"
#include "rules.h"
#include "ruleset.h"

#include "config_falco_engine.h"
#include "falco_common.h"

//
// This class acts as the primary interface between a program and the
// falco rules engine. Falco outputs (writing to files/syslog/etc) are
// handled in a separate class falco_outputs.
//

class falco_engine : public falco_common
{
public:
	falco_engine(bool seed_rng=true, const std::string& alternate_lua_dir=FALCO_ENGINE_SOURCE_LUA_DIR);
	virtual ~falco_engine();

	// A given engine has a version which identifies the fields
	// and rules file format it supports. This version will change
	// any time the code that handles rules files, expression
	// fields, etc, changes.
	static uint32_t engine_version();

	// Print to stdout (using printf) a description of each field supported by this engine.
	// If source is non-empty, only fields for the provided source are printed.
	void list_fields(std::string &source, bool verbose, bool names_only);

	//
	// Load rules either directly or from a filename.
	//
	void load_rules_file(const std::string &rules_filename, bool verbose, bool all_events);
	void load_rules(const std::string &rules_content, bool verbose, bool all_events);

	//
	// Identical to above, but also returns the required engine version for the file/content.
	// (If no required engine version is specified, returns 0).
	//
	void load_rules_file(const std::string &rules_filename, bool verbose, bool all_events, uint64_t &required_engine_version);
	void load_rules(const std::string &rules_content, bool verbose, bool all_events, uint64_t &required_engine_version);

	//
	// Enable/Disable any rules matching the provided substring.
	// If the substring is "", all rules are enabled/disabled.
	// When provided, enable/disable these rules in the
	// context of the provided ruleset. The ruleset (id) can later
	// be passed as an argument to process_event(). This allows
	// for different sets of rules being active at once.
	//
	void enable_rule(const std::string &substring, bool enabled, const std::string &ruleset = s_default_ruleset);


	// Like enable_rule, but the rule name must be an exact match.
	void enable_rule_exact(const std::string &rule_name, bool enabled, const std::string &ruleset = s_default_ruleset);

	//
	// Enable/Disable any rules with any of the provided tags (set, exact matches only)
	//
	void enable_rule_by_tag(const std::set<std::string> &tags, bool enabled, const std::string &ruleset = s_default_ruleset);

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

	// Represents the result of matching an event against a set of
	// rules.
	struct rule_result {
		gen_event *evt;
		std::string rule;
		std::string source;
		falco_common::priority_type priority_num;
		std::string format;
		std::set<std::string> exception_fields;
		std::set<std::string> tags;
	};

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
	std::unique_ptr<rule_result> process_event(std::string &source, gen_event *ev, uint16_t ruleset_id);

	//
	// Wrapper assuming the default ruleset
	//
	std::unique_ptr<rule_result> process_event(std::string &source, gen_event *ev);

	//
	// Configure the engine to support events with the provided
	// source, with the provided filter factory and formatter factory.
	//
	void add_source(const std::string &source,
			std::shared_ptr<gen_event_filter_factory> filter_factory,
			std::shared_ptr<gen_event_formatter_factory> formatter_factory);

	// Return whether or not there is a valid filter/formatter
	// factory for this source.
	bool is_source_valid(const std::string &source);

	//
	// Add a filter for the provided event source to the engine
	//
	void add_filter(std::shared_ptr<gen_event_filter> filter,
			std::string &rule,
			std::string &source,
			std::set<std::string> &tags);

	//
	// Given an event source and ruleset, fill in a bitset
	// containing the event types for which this ruleset can run.
	//
	void evttypes_for_ruleset(std::string &source,
				  std::set<uint16_t> &evttypes,
				  const std::string &ruleset = s_default_ruleset);

	//
	// Given a source and output string, return an
	// gen_event_formatter that can format output strings for an
	// event.
	//
	std::shared_ptr<gen_event_formatter> create_formatter(const std::string &source,
							      const std::string &output);

	// Return whether the provided plugin name + version is
	// compatible with the current set of loaded rules files.
	// required_version will be filled in with the required
	// version when the method returns false.
	bool is_plugin_compatible(const std::string &name, const std::string &version, std::string &required_version);

private:

	//
	// Determine whether the given event should be matched at all
	// against the set of rules, given the current sampling
	// ratio/multiplier.
	//
	inline bool should_drop_evt();

	// Maps from event source to object that can generate filters from rules
	std::map<std::string, std::shared_ptr<gen_event_filter_factory>> m_filter_factories;

	// Maps from event source to object that can format output strings in rules
	std::map<std::string, std::shared_ptr<gen_event_formatter_factory>> m_format_factories;

	// Maps from event source to the set of rules for that event source
	std::map<std::string, std::shared_ptr<falco_ruleset>> m_rulesets;

	std::unique_ptr<falco_rules> m_rules;
	uint16_t m_next_ruleset_id;
	std::map<string, uint16_t> m_known_rulesets;
	falco_common::priority_type m_min_priority;

	// Maps from plugin to a list of required plugin versions
	// found in any loaded rules files.
	std::map<std::string, std::list<std::string>> m_required_plugin_versions;

	void populate_rule_result(unique_ptr<struct rule_result> &res, gen_event *ev);

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
	static const std::string s_default_ruleset;
	uint32_t m_default_ruleset_id;

	std::string m_extra;
	bool m_replace_container_info;
};

