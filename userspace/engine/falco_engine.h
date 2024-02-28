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

#include <atomic>
#include <string>
#include <memory>
#include <set>

#include <nlohmann/json.hpp>

#include "filter_ruleset.h"
#include "rule_loader.h"
#include "rule_loader_reader.h"
#include "rule_loader_collector.h"
#include "rule_loader_compiler.h"
#include "stats_manager.h"
#include "falco_common.h"
#include "falco_source.h"
#include "falco_load_result.h"
#include "filter_details_resolver.h"

//
// This class acts as the primary interface between a program and the
// falco rules engine. Falco outputs (writing to files/syslog/etc) are
// handled in a separate class falco_outputs.
//

class falco_engine
{
public:
	explicit falco_engine(bool seed_rng=true);
	virtual ~falco_engine();

	// A given engine has a version which identifies the fields
	// and rules file format it supports. This version will change
	// any time the code that handles rules files, expression
	// fields, etc, changes.
	static sinsp_version engine_version();

	// Engine version used to be represented as a simple progressive
	// number. With the new semver schema, the number now represents
	// the semver minor number. This function converts the legacy version 
	// number to the new semver schema.
	static inline sinsp_version get_implicit_version(uint32_t minor)
	{
		return rule_loader::reader::get_implicit_engine_version(minor);
	}

	// Print to stdout (using printf) a description of each field supported by this engine.
	// If source is non-empty, only fields for the provided source are printed.
	void list_fields(const std::string &source, bool verbose, bool names_only, bool markdown) const;

	// Provide an alternate rule reader, collector, and compiler
	// to compile any rules provided via load_rules*
	void set_rule_reader(std::shared_ptr<rule_loader::reader> reader);
	std::shared_ptr<rule_loader::reader> get_rule_reader();

	void set_rule_collector(std::shared_ptr<rule_loader::collector> collector);
	std::shared_ptr<rule_loader::collector> get_rule_collector();

	void set_rule_compiler(std::shared_ptr<rule_loader::compiler> compiler);
	std::shared_ptr<rule_loader::compiler> get_rule_compiler();

	//
	// Load rules and returns a result object.
	//
	std::unique_ptr<falco::load_result> load_rules(const std::string &rules_content, const std::string &name);

	//
	// Enable/Disable any rules matching the provided substring.
	// If the substring is "", all rules are enabled/disabled.
	// When provided, enable/disable these rules in the
	// context of the provided ruleset. The ruleset (id) can later
	// be passed as an argument to process_event(). This allows
	// for different sets of rules being active at once.
	// The rules are matched against the rulesets of all the defined sources.
	//
	void enable_rule(const std::string &substring, bool enabled, const std::string &ruleset = s_default_ruleset);

	// Same as above but providing a ruleset id instead
	void enable_rule(const std::string &substring, bool enabled, const uint16_t ruleset_id);

	// Like enable_rule, but the rule name must be an exact match.
	void enable_rule_exact(const std::string &rule_name, bool enabled, const std::string &ruleset = s_default_ruleset);

	// Same as above but providing a ruleset id instead
	void enable_rule_exact(const std::string &rule_name, bool enabled, const uint16_t ruleset_id);

	//
	// Enable/Disable any rules with any of the provided tags (set, exact matches only)
	//
	void enable_rule_by_tag(const std::set<std::string> &tags, bool enabled, const std::string &ruleset = s_default_ruleset);

	// Same as above but providing a ruleset id instead
	void enable_rule_by_tag(const std::set<std::string> &tags, bool enabled, const uint16_t ruleset_id);

	//
	// Must be called after the engine has been configured and all rulesets
	// have been loaded and enabled/disabled.
	// This does not change the engine configuration nor the loaded/enabled rule
	// setup, and does not affect the functional behavior.
	// Internally, this can be used to release unused resources before starting
	// processing events with process_event().
	//
	void complete_rule_loading() const;

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
	// across all sources.
	//
	uint64_t num_rules_for_ruleset(const std::string &ruleset);

	//
	// Print details on the given rule. If rule is NULL, print
	// details on all rules.
	//
	nlohmann::json describe_rule(std::string *rule_name, const std::vector<std::shared_ptr<sinsp_plugin>>& plugins) const;

	//
	// Print statistics on how many events matched each rule.
	//
	void print_stats() const;

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
	// add k8s/container information to outputs when
	// available.
	//
	void set_extra(const std::string &extra, bool replace_container_info);

	// Represents the result of matching an event against a set of
	// rules.
	struct rule_result {
		sinsp_evt *evt;
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
	// the rule that matched. If no rule matched, returns nullptr.
	//
	// This method should be invoked only after having initialized and
	// configured the engine. In particular, invoking this with a source_idx
	// not previosly-returned by a call to add_source() would cause a
	// falco_exception to be thrown.
	//
	// This method is thread-safe only with the assumption that every invoker
	// uses a different source_idx. Moreover, each invoker must not switch
	// source_idx in subsequent invocations of this method.
	// Considering that each invoker is related to a unique event source, it
	// is safe to assume that each invoker will pass a different event
	// to this method too, since two distinct sources cannot possibly produce
	// the same event. Lastly, filterchecks and formatters (and their factories)
	// that are used to populate the conditions for a given event-source
	// ruleset must not be reused across rulesets of other event sources.
	// These assumptions guarantee thread-safety because internally the engine
	// is partitioned by event sources. However, each ruleset assigned to each
	// event source is not thread-safe of its own, so invoking this method
	// concurrently with the same source_idx would inherently cause data races
	// and lead to undefined behavior.
	std::unique_ptr<std::vector<rule_result>> process_event(std::size_t source_idx,
		sinsp_evt *ev, uint16_t ruleset_id, falco_common::rule_matching strategy);

	//
	// Wrapper assuming the default ruleset.
	//
	// This inherits the same thread-safety guarantees.
	//
	std::unique_ptr<std::vector<rule_result>> process_event(std::size_t source_idx,
		sinsp_evt *ev, falco_common::rule_matching strategy);

	//
	// Configure the engine to support events with the provided
	// source, with the provided filter factory and formatter factory.
	// Return source index for fast lookup.
	//
	std::size_t add_source(const std::string &source,
			       std::shared_ptr<sinsp_filter_factory> filter_factory,
			       std::shared_ptr<sinsp_evt_formatter_factory> formatter_factory);

	//
	// Equivalent to above, but allows specifying a ruleset factory
	// for the newly added source.
	//
	std::size_t add_source(const std::string &source,
			       std::shared_ptr<sinsp_filter_factory> filter_factory,
			       std::shared_ptr<sinsp_evt_formatter_factory> formatter_factory,
			       std::shared_ptr<filter_ruleset_factory> ruleset_factory);

	// Return whether or not there is a valid filter/formatter
	// factory for this source.
	bool is_source_valid(const std::string &source) const;

	//
	// Given a source, return a formatter factory that can create
	// filters for events of that source.
	//
	std::shared_ptr<sinsp_filter_factory> filter_factory_for_source(const std::string& source);
	std::shared_ptr<sinsp_filter_factory> filter_factory_for_source(std::size_t source_idx);

	//
	// Given a source, return a formatter factory that can create
	// formatters for an event.
	//
	std::shared_ptr<sinsp_evt_formatter_factory> formatter_factory_for_source(const std::string& source);
	std::shared_ptr<sinsp_evt_formatter_factory> formatter_factory_for_source(std::size_t source_idx);

	//
	// Given a source, return a ruleset factory that can create
	// rulesets for that source.
	//
	std::shared_ptr<filter_ruleset_factory> ruleset_factory_for_source(const std::string& source);
	std::shared_ptr<filter_ruleset_factory> ruleset_factory_for_source(std::size_t source_idx);

	// Return the filter_ruleset used for a given source.
	std::shared_ptr<filter_ruleset> ruleset_for_source(const std::string& source);
	std::shared_ptr<filter_ruleset> ruleset_for_source(std::size_t source_idx);

	//
	// Given an event source and ruleset, fill in a bitset
	// containing the event types for which this ruleset can run.
	// note(jasondellaluce): this is deprecated, must use the new
	// typing-improved `enabled_event_codes` and `enabled_sc_codes` instead
	// todo(jasondellaluce): remove this in future code refactors
	//
	void evttypes_for_ruleset(const std::string &source,
				  std::set<uint16_t> &evttypes,
				  const std::string &ruleset = s_default_ruleset);

	//
	// Given an event source and ruleset, return the set of ppm_sc_codes
	// for which this ruleset can run and match events.
	//
	libsinsp::events::set<ppm_sc_code> sc_codes_for_ruleset(
				  const std::string &source,
				  const std::string &ruleset = s_default_ruleset);
	
	//
	// Given an event source and ruleset, return the set of ppm_event_codes
	// for which this ruleset can run and match events.
	//
	libsinsp::events::set<ppm_event_code> event_codes_for_ruleset(
				  const std::string &source,
				  const std::string &ruleset = s_default_ruleset);

	//
	// Given a source and output string, return an
	// sinsp_evt_formatter that can format output strings for an
	// event.
	//
	std::shared_ptr<sinsp_evt_formatter> create_formatter(const std::string &source,
							      const std::string &output) const;

	// The rule loader definition is aliased as it is exactly what we need
	typedef rule_loader::plugin_version_info::requirement plugin_version_requirement;

	//
	// Returns true if the provided list of plugins satisfies all the
	// version requirements of the internal definitions. The list is represented
	// as a vectors of pair of strings. In each pair, the first element is
	// the name of the plugin and the second element is its version.
	// If false is returned, err is filled with error causing the check failure.
	//
	bool check_plugin_requirements(
		const std::vector<plugin_version_requirement>& plugins,
		std::string& err) const;

private:
	// Create a ruleset using the provided factory and set the
	// engine state funcs for it.
	std::shared_ptr<filter_ruleset> create_ruleset(std::shared_ptr<filter_ruleset_factory>& ruleset_factory);

	// Functions to retrieve state from this engine
	void fill_engine_state_funcs(filter_ruleset::engine_state_funcs& engine_state);

	filter_ruleset::engine_state_funcs m_engine_state;

	// Throws falco_exception if the file can not be read
	void read_file(const std::string& filename, std::string& contents);

	indexed_vector<falco_source> m_sources;

	inline const falco_source* find_source(std::size_t index)
	{
		const falco_source *source;

		if(index == m_syscall_source_idx)
		{
			if(m_syscall_source == NULL)
			{
				m_syscall_source = m_sources.at(m_syscall_source_idx);
				if(!m_syscall_source)
				{
					throw falco_exception("Unknown event source index " + std::to_string(index));
				}
			}

			source = m_syscall_source;
		}
		else
		{
			source = m_sources.at(index);
			if(!source)
			{
				throw falco_exception("Unknown event source index " + std::to_string(index));
			}
		}

		return source;
	}

	inline const falco_source* find_source(const std::string& name) const
	{
		auto ret = m_sources.at(name);
		if(!ret)
		{
			throw falco_exception("Unknown event source " + name);
		}
		return ret;
	}

	// To allow the engine to be extremely fast for syscalls (can
	// be > 1M events/sec), we save the syscall source/source_idx
	// separately and check it explicitly in process_event()
	const falco_source* m_syscall_source;
	std::atomic<size_t> m_syscall_source_idx;

	//
	// Determine whether the given event should be matched at all
	// against the set of rules, given the current sampling
	// ratio/multiplier.
	//
	inline bool should_drop_evt() const;

	// Retrieve json details from rules, macros, lists
	void get_json_details(
		nlohmann::json& out,
		const falco_rule& r,
		const rule_loader::rule_info& info,
		const std::vector<std::shared_ptr<sinsp_plugin>>& plugins) const;
	void get_json_details(
		nlohmann::json& out,
		const falco_macro& m,
		const rule_loader::macro_info& info,
		const std::vector<std::shared_ptr<sinsp_plugin>>& plugins) const;
	void get_json_details(
		nlohmann::json& out,
		const falco_list& l,
		const rule_loader::list_info& info,
		const std::vector<std::shared_ptr<sinsp_plugin>>& plugins) const;
	void get_json_evt_types(
		nlohmann::json& out,
		const std::string& source,
		libsinsp::filter::ast::expr* ast) const;
	void get_json_used_plugins(
		nlohmann::json& out,
		const std::string& source,
		const std::unordered_set<std::string>& evttypes,
		const std::unordered_set<std::string>& fields,
		const std::vector<std::shared_ptr<sinsp_plugin>>& plugins) const;

	indexed_vector<falco_rule> m_rules;
	std::shared_ptr<rule_loader::reader> m_rule_reader;
	std::shared_ptr<rule_loader::collector> m_rule_collector;
	std::shared_ptr<rule_loader::compiler> m_rule_compiler;
	stats_manager m_rule_stats_manager;

	uint16_t m_next_ruleset_id;
	std::map<std::string, uint16_t> m_known_rulesets;
	falco_common::priority_type m_min_priority;

	std::unique_ptr<rule_loader::compile_output> m_last_compile_output;

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

	static const std::string s_default_ruleset;
	uint32_t m_default_ruleset_id;

	std::string m_extra;
	bool m_replace_container_info;
};
