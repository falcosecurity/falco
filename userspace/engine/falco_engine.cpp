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

#include <cstdlib>
#ifndef _WIN32
#include <unistd.h>
#else
#include <stdlib.h>
#include <io.h>
#define srandom srand
#define random rand
#endif
#include <string>
#include <fstream>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <libsinsp/sinsp.h>
#include <libsinsp/plugin.h>
#include <libsinsp/utils.h>

#include "falco_engine.h"
#include "falco_utils.h"
#include "falco_engine_version.h"

#include "formats.h"

#include "evttype_index_ruleset.h"

const std::string falco_engine::s_default_ruleset = "falco-default-ruleset";

using namespace falco;

falco_engine::falco_engine(bool seed_rng)
	: m_syscall_source(NULL),
	  m_syscall_source_idx(SIZE_MAX),
	  m_rule_reader(std::make_shared<rule_loader::reader>()),
	  m_rule_collector(std::make_shared<rule_loader::collector>()),
	  m_rule_compiler(std::make_shared<rule_loader::compiler>()),
	  m_next_ruleset_id(0),
	  m_min_priority(falco_common::PRIORITY_DEBUG),
	  m_sampling_ratio(1), m_sampling_multiplier(0),
	  m_replace_container_info(false)
{
	if(seed_rng)
	{
		srandom((unsigned) getpid());
	}

	m_default_ruleset_id = find_ruleset_id(s_default_ruleset);

	fill_engine_state_funcs(m_engine_state);
}

falco_engine::~falco_engine()
{
	m_rules.clear();
	m_rule_collector->clear();
	m_rule_stats_manager.clear();
	m_sources.clear();
}

sinsp_version falco_engine::engine_version()
{
	return sinsp_version(FALCO_ENGINE_VERSION);
}

void falco_engine::set_rule_reader(std::shared_ptr<rule_loader::reader> reader)
{
	m_rule_reader = reader;
}

std::shared_ptr<rule_loader::reader> falco_engine::get_rule_reader()
{
	return m_rule_reader;
}

void falco_engine::set_rule_collector(std::shared_ptr<rule_loader::collector> collector)
{
	m_rule_collector = collector;
}

std::shared_ptr<rule_loader::collector> falco_engine::get_rule_collector()
{
	return m_rule_collector;
}

void falco_engine::set_rule_compiler(std::shared_ptr<rule_loader::compiler> compiler)
{
	m_rule_compiler = compiler;
}

std::shared_ptr<rule_loader::compiler> falco_engine::get_rule_compiler()
{
	return m_rule_compiler;
}

// Return a key that uniquely represents a field class.
// For now, we assume name + shortdesc is unique.
static std::string fieldclass_key(const sinsp_filter_factory::filter_fieldclass_info &fld_info)
{
	return fld_info.name + fld_info.shortdesc;
}

void falco_engine::list_fields(const std::string &source, bool verbose, bool names_only, bool markdown) const
{
	// Maps from field class name + short desc to list of event
	// sources for which this field class can be used.
	std::map<std::string,std::set<std::string>> fieldclass_event_sources;

	// Do a first pass to group together classes that are
	// applicable to multiple event sources.
	for(const auto &it : m_sources)
	{
		if(source != "" && source != it.name)
		{
			continue;
		}

		for(const auto &fld_class : it.filter_factory->get_fields())
		{
			fieldclass_event_sources[fieldclass_key(fld_class)].insert(it.name);
		}
	}

	// The set of field classes already printed. Used to avoid
	// printing field classes multiple times for different sources
	std::set<std::string> seen_fieldclasses;

	// In the second pass, actually print info, skipping duplicate
	// field classes and also printing info on supported sources.
	for(const auto &it : m_sources)
	{
		if(source != "" && source != it.name)
		{
			continue;
		}

		for(auto &fld_class : it.filter_factory->get_fields())
		{
			std::string key = fieldclass_key(fld_class);

			if(seen_fieldclasses.find(key) != seen_fieldclasses.end())
			{
				continue;
			}

			seen_fieldclasses.insert(key);

			if(names_only)
			{
				for(auto &field : fld_class.fields)
				{
					if(field.is_skippable() || field.is_deprecated())
					{
						continue;
					}

					printf("%s\n", field.name.c_str());
				}
			}
			else if (markdown)
			{
				printf("%s\n", fld_class.as_markdown(
									fieldclass_event_sources[fieldclass_key(fld_class)]).c_str());
			}
			else
			{
				printf("%s\n", fld_class.as_string(verbose,
								   fieldclass_event_sources[fieldclass_key(fld_class)]).c_str());
			}
		}
	}
}

std::unique_ptr<load_result> falco_engine::load_rules(const std::string &rules_content, const std::string &name)
{
	rule_loader::configuration cfg(rules_content, m_sources, name);
	cfg.output_extra = m_extra;
	cfg.replace_output_container_info = m_replace_container_info;

	// read rules YAML file and collect its definitions
	if(m_rule_reader->read(cfg, *(m_rule_collector.get())))
	{
		// compile the definitions (resolve macro/list refs, exceptions, ...)
		m_last_compile_output = m_rule_compiler->new_compile_output();
		m_rule_compiler->compile(cfg, *(m_rule_collector.get()), *m_last_compile_output.get());

		// clear the rules known by the engine and each ruleset
		m_rules.clear();
		for (auto &src : m_sources)
		// add rules to each ruleset
		{
			src.ruleset = create_ruleset(src.ruleset_factory);
			src.ruleset->add_compile_output(*(m_last_compile_output.get()),
							m_min_priority,
							src.name);
		}

		// add rules to the engine and the rulesets
		for (const auto& rule : m_last_compile_output->rules)
		{
			auto info = m_rule_collector->rules().at(rule.name);
			if (!info)
			{
				// this is just defensive, it should never happen
				throw falco_exception("can't find internal rule info at name: " + name);
			}

			auto source = find_source(rule.source);
			auto rule_id = m_rules.insert(rule, rule.name);
			if (rule_id != rule.id)
			{
				throw falco_exception("Incompatible ID for rule: " + rule.name +
						      " | compiled ID: " + std::to_string(rule.id) +
						      " | stats_mgr ID: " + std::to_string(rule_id));
			}

			// By default rules are enabled/disabled for the default ruleset
			// skip the rule if below the minimum priority
			if (rule.priority > m_min_priority)
			{
				continue;
			}
			if(info->enabled)
			{
				source->ruleset->enable(rule.name, true, m_default_ruleset_id);
			}
			else
			{
				source->ruleset->disable(rule.name, true, m_default_ruleset_id);
			}
		}
	}

	if (cfg.res->successful())
	{
		m_rule_stats_manager.clear();
		for (const auto &r : m_rules)
		{
			m_rule_stats_manager.on_rule_loaded(r);
		}
	}

	return std::move(cfg.res);
}

void falco_engine::enable_rule(const std::string &substring, bool enabled, const std::string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	enable_rule(substring, enabled, ruleset_id);
}

void falco_engine::enable_rule(const std::string &substring, bool enabled, const uint16_t ruleset_id)
{
	bool match_exact = false;

	for(const auto &it : m_sources)
	{
		if(enabled)
		{
			it.ruleset->enable(substring, match_exact, ruleset_id);
		}
		else
		{
			it.ruleset->disable(substring, match_exact, ruleset_id);
		}
	}
}

void falco_engine::enable_rule_exact(const std::string &rule_name, bool enabled, const std::string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	enable_rule_exact(rule_name, enabled, ruleset_id);
}

void falco_engine::enable_rule_exact(const std::string &rule_name, bool enabled, const uint16_t ruleset_id)
{
	bool match_exact = true;

	for(const auto &it : m_sources)
	{
		if(enabled)
		{
			it.ruleset->enable(rule_name, match_exact, ruleset_id);
		}
		else
		{
			it.ruleset->disable(rule_name, match_exact, ruleset_id);
		}
	}
}

void falco_engine::enable_rule_by_tag(const std::set<std::string> &tags, bool enabled, const std::string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);

	enable_rule_by_tag(tags, enabled, ruleset_id);
}

void falco_engine::enable_rule_by_tag(const std::set<std::string> &tags, bool enabled, const uint16_t ruleset_id)
{
	for(const auto &it : m_sources)
	{
		if(enabled)
		{
			it.ruleset->enable_tags(tags, ruleset_id);
		}
		else
		{
			it.ruleset->disable_tags(tags, ruleset_id);
		}
	}
}

void falco_engine::set_min_priority(falco_common::priority_type priority)
{
	m_min_priority = priority;
}

uint16_t falco_engine::find_ruleset_id(const std::string &ruleset)
{
	auto it = m_known_rulesets.lower_bound(ruleset);
	if(it == m_known_rulesets.end() || it->first != ruleset)
	{
		it = m_known_rulesets.emplace_hint(it,
						   std::make_pair(ruleset, m_next_ruleset_id++));
	}
	return it->second;
}

uint64_t falco_engine::num_rules_for_ruleset(const std::string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);
	uint64_t ret = 0;
	for (const auto &src : m_sources)
	{
		ret += src.ruleset->enabled_count(ruleset_id);
	}
	return ret;
}

void falco_engine::evttypes_for_ruleset(const std::string &source, std::set<uint16_t> &evttypes, const std::string &ruleset)
{
	find_source(source)->ruleset->enabled_evttypes(evttypes, find_ruleset_id(ruleset));
}

libsinsp::events::set<ppm_sc_code> falco_engine::sc_codes_for_ruleset(const std::string &source, const std::string &ruleset)
{
	return find_source(source)->ruleset->enabled_sc_codes(find_ruleset_id(ruleset));
}

libsinsp::events::set<ppm_event_code> falco_engine::event_codes_for_ruleset(const std::string &source, const std::string &ruleset)
{
	return find_source(source)->ruleset->enabled_event_codes(find_ruleset_id(ruleset));
}

std::shared_ptr<sinsp_evt_formatter> falco_engine::create_formatter(const std::string &source,
								    const std::string &output) const
{
	return find_source(source)->formatter_factory->create_formatter(output);
}

std::unique_ptr<std::vector<falco_engine::rule_result>> falco_engine::process_event(std::size_t source_idx,
	sinsp_evt *ev, uint16_t ruleset_id, falco_common::rule_matching strategy)
{
	// note: there are no thread-safety guarantees on the filter_ruleset::run()
	// method, but the thread-safety assumptions of falco_engine::process_event()
	// imply that concurrent invokers use different and non-switchable values of
	// source_idx, which means that at any time each filter_ruleset will only
	// be accessed by a single thread.

	const falco_source *source = find_source(source_idx);

	if(should_drop_evt() || !source)
	{
		return nullptr;
	}

	switch (strategy)
	{
	case falco_common::rule_matching::ALL:
		if (source->m_rules.size() > 0)
		{
			source->m_rules.clear();
		}
		if (!source->ruleset->run(ev, source->m_rules, ruleset_id))
		{
			return nullptr;
		}
		break;
	case falco_common::rule_matching::FIRST:
		if (source->m_rules.size() != 1)
		{
			source->m_rules.resize(1);
		}
		if (!source->ruleset->run(ev, source->m_rules[0], ruleset_id))
		{
			return nullptr;
		}
		break;
	}

	auto res = std::make_unique<std::vector<falco_engine::rule_result>>();
	for(const auto& rule : source->m_rules)
	{
		rule_result rule_result;
		rule_result.evt = ev;
		rule_result.rule = rule.name;
		rule_result.source = rule.source;
		rule_result.format = rule.output;
		rule_result.priority_num = rule.priority;
		rule_result.tags = rule.tags;
		rule_result.exception_fields = rule.exception_fields;
		m_rule_stats_manager.on_event(rule);
		res->push_back(rule_result);
	}

	return res;
}

std::unique_ptr<std::vector<falco_engine::rule_result>> falco_engine::process_event(std::size_t source_idx,
	sinsp_evt *ev, falco_common::rule_matching strategy)
{
	return process_event(source_idx, ev, m_default_ruleset_id, strategy);
}

std::size_t falco_engine::add_source(const std::string &source,
				     std::shared_ptr<sinsp_filter_factory> filter_factory,
				     std::shared_ptr<sinsp_evt_formatter_factory> formatter_factory)
{
	// evttype_index_ruleset is the default ruleset implementation
	size_t idx = add_source(source, filter_factory, formatter_factory,
	                        std::make_shared<evttype_index_ruleset_factory>(filter_factory));

	if(source == falco_common::syscall_source)
	{
		m_syscall_source_idx = idx;
	}

	return idx;
}

std::size_t falco_engine::add_source(const std::string &source,
	std::shared_ptr<sinsp_filter_factory> filter_factory,
	std::shared_ptr<sinsp_evt_formatter_factory> formatter_factory,
	std::shared_ptr<filter_ruleset_factory> ruleset_factory)
{
	falco_source src;
	src.name = source;
	src.filter_factory = filter_factory;
	src.formatter_factory = formatter_factory;
	src.ruleset_factory = ruleset_factory;
	src.ruleset = create_ruleset(src.ruleset_factory);
	return m_sources.insert(src, source);
}

template <typename T> inline nlohmann::json sequence_to_json_array(const T& seq)
{
	nlohmann::json ret = nlohmann::json::array();
	for (const auto& v : seq)
	{
		ret.push_back(v);
	}
	return ret;
}

nlohmann::json falco_engine::describe_rule(std::string *rule_name, const std::vector<std::shared_ptr<sinsp_plugin>>& plugins) const
{
	// use previously-loaded collector definitions and the compiled
	// output of rules, macros, and lists.
	if (m_last_compile_output == nullptr)
	{
		throw falco_exception("rules must be loaded before describing them");
	}

	// use collected and compiled info to print a json output
	nlohmann::json output;
	if(!rule_name)
	{
		// Store required engine version
		auto required_engine_version = m_rule_collector->required_engine_version();
		output["required_engine_version"] = required_engine_version.version.as_string();

		// Store required plugin versions
		nlohmann::json plugin_versions = nlohmann::json::array();
		auto required_plugin_versions = m_rule_collector->required_plugin_versions();
		for(const auto& req : required_plugin_versions)
		{
			nlohmann::json r;
			r["name"] = req.at(0).name;
			r["version"] = req.at(0).version;

			nlohmann::json alternatives = nlohmann::json::array();
			for(size_t i = 1; i < req.size(); i++)
			{
				nlohmann::json alternative;
				alternative["name"] = req[i].name;
				alternative["version"] = req[i].version;
				alternatives.push_back(std::move(alternative));
			}
			r["alternatives"] = std::move(alternatives);

			plugin_versions.push_back(std::move(r));
		}
		output["required_plugin_versions"] = std::move(plugin_versions);

		// Store information about rules
		nlohmann::json rules_array = nlohmann::json::array();
		for(const auto& rule : m_last_compile_output->rules)
		{
			auto info = m_rule_collector->rules().at(rule.name);
			nlohmann::json details;
			get_json_details(details, rule, *info, plugins);
			rules_array.push_back(std::move(details));
		}
		output["rules"] = std::move(rules_array);

		// Store information about macros
		nlohmann::json macros_array = nlohmann::json::array();
		for(const auto &macro : m_last_compile_output->macros)
		{
			auto info = m_rule_collector->macros().at(macro.name);
			nlohmann::json details;
			get_json_details(details, macro, *info, plugins);
			macros_array.push_back(std::move(details));
		}
		output["macros"] = std::move(macros_array);

		// Store information about lists
		nlohmann::json lists_array = nlohmann::json::array();
		for(const auto &list : m_last_compile_output->lists)
		{
			auto info = m_rule_collector->lists().at(list.name);
			nlohmann::json details;
			get_json_details(details, list, *info, plugins);
			lists_array.push_back(std::move(details));
		}
		output["lists"] = std::move(lists_array);
	}
	else
	{
		// build json information for just the specified rule
		auto ri = m_rule_collector->rules().at(*rule_name);
		if(ri == nullptr || ri->unknown_source)
		{
			throw falco_exception("Rule \"" + *rule_name + "\" is not loaded");
		}
		auto rule = m_rules.at(ri->name);

		nlohmann::json details;
		get_json_details(details, *rule, *ri, plugins);
		nlohmann::json rules_array = nlohmann::json::array();
		rules_array.push_back(std::move(details));
		output["rules"] = std::move(rules_array);
	}

	return output;
}

void falco_engine::get_json_details(
	nlohmann::json &out,
	const falco_rule &r,
	const rule_loader::rule_info &info,
	const std::vector<std::shared_ptr<sinsp_plugin>>& plugins) const
{
	nlohmann::json rule_info;

	// Fill general rule information
	rule_info["name"] = r.name;
	rule_info["condition"] = info.cond;
	rule_info["priority"] = format_priority(r.priority, false);
	rule_info["output"] = info.output;
	rule_info["description"] = r.description;
	rule_info["enabled"] = info.enabled;
	rule_info["source"] = r.source;
	rule_info["tags"] = sequence_to_json_array(info.tags);
	out["info"] = std::move(rule_info);

	// Parse rule condition and build the non-compiled AST
	// Assumption: no error because rules have already been loaded.
	auto ast = libsinsp::filter::parser(info.cond).parse();

	// get details related to the condition's filter
	filter_details details;
	filter_details compiled_details;
	nlohmann::json json_details;
	for(const auto &m : m_rule_collector->macros())
	{
		details.known_macros.insert(m.name);
		compiled_details.known_macros.insert(m.name);
	}
	for(const auto &l : m_rule_collector->lists())
	{
		details.known_lists.insert(l.name);
		compiled_details.known_lists.insert(l.name);
	}
	filter_details_resolver().run(ast.get(), details);
	filter_details_resolver().run(r.condition.get(), compiled_details);

	out["details"]["macros"] = sequence_to_json_array(details.macros);
	out["details"]["lists"] = sequence_to_json_array(details.lists);
	out["details"]["condition_operators"] = sequence_to_json_array(compiled_details.operators);
	out["details"]["condition_fields"] = sequence_to_json_array(compiled_details.fields);

	// Get fields from output string
	auto fmt = create_formatter(r.source, r.output);
	std::vector<std::string> out_fields;
	fmt->get_field_names(out_fields);
	out["details"]["output_fields"] = sequence_to_json_array(out_fields);

	// Get fields from exceptions
	out["details"]["exception_fields"] = sequence_to_json_array(r.exception_fields);

	// Get names and operators from exceptions
	std::unordered_set<std::string> exception_names;
	std::unordered_set<std::string> exception_operators;
	for(const auto &e : info.exceptions)
	{
		exception_names.insert(e.name);
		if(e.comps.is_list)
		{
			for(const auto& c : e.comps.items)
			{
				if(c.is_list)
				{
					// considering max two levels of lists
					for(const auto& i : c.items)
					{
						exception_operators.insert(i.item);
					}
				}
				else
				{
					exception_operators.insert(c.item);
				}
			}
		}
		else
		{
			exception_operators.insert(e.comps.item);
		}
	}
	out["details"]["exception_names"] = sequence_to_json_array(exception_names);
	out["details"]["exception_operators"] = sequence_to_json_array(exception_operators);

	// Store event types
	nlohmann::json events;
	get_json_evt_types(events, info.source, r.condition.get());
	out["details"]["events"] = std::move(events);

	// Store compiled condition and output
	out["details"]["condition_compiled"] = libsinsp::filter::ast::as_string(r.condition.get());
	out["details"]["output_compiled"] = r.output;

	// Compute the plugins that are actually used by this rule. This is involves:
	// - The rule's event source, that can be implemented by a plugin
	// - The fields used in the rule's condition, output, and exceptions
	// - The evt types used in the rule's condition checks, that can potentially
	//   match plugin-provided async events
	nlohmann::json used_plugins;
	// note: making a union of conditions's and output's fields
	// note: the condition's AST accounts for all the resolved refs and exceptions
	compiled_details.fields.insert(out_fields.begin(), out_fields.end());
	get_json_used_plugins(used_plugins, info.source, compiled_details.evtnames, compiled_details.fields, plugins);
	out["details"]["plugins"] = std::move(used_plugins);
}

void falco_engine::get_json_details(
	nlohmann::json& out,
	const falco_macro& macro,
	const rule_loader::macro_info& info,
	const std::vector<std::shared_ptr<sinsp_plugin>>& plugins) const
{
	nlohmann::json macro_info;

	macro_info["name"] = macro.name;
	macro_info["condition"] = info.cond;
	out["info"] = std::move(macro_info);

	// Parse the macro condition and build the non-compiled AST
	// Assumption: no exception because rules have already been loaded.
	auto ast = libsinsp::filter::parser(info.cond).parse();

	// get details related to the condition's filter
	filter_details details;
	filter_details compiled_details;
	nlohmann::json json_details;
	for(const auto &m : m_rule_collector->macros())
	{
		details.known_macros.insert(m.name);
		compiled_details.known_macros.insert(m.name);
	}
	for(const auto &l : m_rule_collector->lists())
	{
		details.known_lists.insert(l.name);
		compiled_details.known_lists.insert(l.name);
	}
	filter_details_resolver().run(ast.get(), details);
	filter_details_resolver().run(macro.condition.get(), compiled_details);

	out["details"]["used"] = macro.used;
	out["details"]["macros"] = sequence_to_json_array(details.macros);
	out["details"]["lists"] = sequence_to_json_array(details.lists);
	out["details"]["condition_operators"] = sequence_to_json_array(compiled_details.operators);
	out["details"]["condition_fields"] = sequence_to_json_array(compiled_details.fields);

	// Store event types
	nlohmann::json events;
	get_json_evt_types(events, "", macro.condition.get());
	out["details"]["events"] = std::move(events);

	// Store compiled condition
	out["details"]["condition_compiled"] = libsinsp::filter::ast::as_string(macro.condition.get());

	// Compute the plugins that are actually used by this macro.
	// Note: macros have no specific source, we need to set an empty list of used
	// plugins because we can't be certain about their actual usage. For example,
	// if a macro uses a plugin's field, we can't be sure which plugin actually
	// is used until we resolve the macro ref in a rule providing a source for
	// disambiguation.
	out["details"]["plugins"] = nlohmann::json::array();
}

void falco_engine::get_json_details(
	nlohmann::json& out,
	const falco_list& l,
	const rule_loader::list_info& info,
	const std::vector<std::shared_ptr<sinsp_plugin>>& plugins) const
{
	nlohmann::json list_info;
	list_info["name"] = l.name;

	// note: the syntactic definitions still has the list refs unresolved
	nlohmann::json items = nlohmann::json::array();
	std::unordered_set<std::string> lists;
	for(const auto &i : info.items)
	{
		// if an item is present in the syntactic def of a list, but not
		// on the compiled_items of the same list, then we can assume it
		// being a resolved list ref
		if(std::find(l.items.begin(), l.items.end(), i) == l.items.end())
		{
			lists.insert(i);
			continue;
		}
		items.push_back(std::move(i));
	}

	list_info["items"] = std::move(items);
	out["info"] = std::move(list_info);
	out["details"]["used"] = l.used;
	out["details"]["lists"] = sequence_to_json_array(lists);
	out["details"]["items_compiled"] = sequence_to_json_array(l.items);
	out["details"]["plugins"] = nlohmann::json::array(); // always empty
}

void falco_engine::get_json_evt_types(
	nlohmann::json& out,
	const std::string& source,
	libsinsp::filter::ast::expr* ast) const
{
	// note: this duplicates part of the logic of evttype_index_ruleset,
	// not good but it's our best option for now
	if (source.empty() || source == falco_common::syscall_source)
	{
		auto evtcodes = libsinsp::filter::ast::ppm_event_codes(ast);
		evtcodes.insert(ppm_event_code::PPME_ASYNCEVENT_E);
		auto syscodes = libsinsp::filter::ast::ppm_sc_codes(ast);
		auto syscodes_to_evt_names = libsinsp::events::sc_set_to_event_names(syscodes);
		auto evtcodes_to_evt_names = libsinsp::events::event_set_to_names(evtcodes, false);
		out = sequence_to_json_array(unordered_set_union(syscodes_to_evt_names, evtcodes_to_evt_names));
	}
	else
	{
		out = sequence_to_json_array(libsinsp::events::event_set_to_names(
			{ppm_event_code::PPME_PLUGINEVENT_E, ppm_event_code::PPME_ASYNCEVENT_E}));
	}
}

void falco_engine::get_json_used_plugins(
	nlohmann::json& out,
	const std::string& source,
	const std::unordered_set<std::string>& evtnames,
	const std::unordered_set<std::string>& fields,
	const std::vector<std::shared_ptr<sinsp_plugin>>& plugins) const
{
	// note: condition and output fields may have an argument, so
	// we need to isolate the field names
	std::unordered_set<std::string> fieldnames;
	for (const auto &f: fields)
	{
		auto argpos = f.find('[');
		if (argpos != std::string::npos)
		{
			fieldnames.insert(f.substr(0, argpos));
		}
		else
		{
			fieldnames.insert(f);
		}
	}

	std::unordered_set<std::string> used_plugins;
	for (const auto& p : plugins)
	{
		bool used = false;
		if (p->caps() & CAP_SOURCING)
		{
			// The rule's source is implemented by a plugin with event
			// sourcing capability.
			// Note: if Falco loads two plugins implementing the same source,
			// they will both be included in the list.
			if (!used && p->event_source() == source)
			{
				used_plugins.insert(p->name());
				used = true;
			}
		}
		if (!used && p->caps() & CAP_EXTRACTION)
		{
			// The rule uses a field implemented by a plugin with field
			// extraction capability that is compatible with the rule's source.
			// Note: here we're assuming that Falco will prevent loading
			// plugins implementing fields with the same name for the same
			// event source (implemented in init_inspectors app action).
			if (sinsp_plugin::is_source_compatible(p->extract_event_sources(), source))
			{
				for (const auto &f : p->fields())
				{
					if (!used && fieldnames.find(f.m_name) != fieldnames.end())
					{
						used_plugins.insert(p->name());
						used = true;
						break;
					}
				}
			}
		}
		if (!used && p->caps() & CAP_ASYNC)
		{
			// The rule matches an event type implemented by a plugin with
			// async events capability that is compatible with the rule's source.
			// Note: if Falco loads two plugins implementing async events with
			// the same name, they will both be included in the list.
			if (sinsp_plugin::is_source_compatible(p->async_event_sources(), source))
			{
				for (const auto &n : p->async_event_names())
				{
					if (!used && evtnames.find(n) != evtnames.end())
					{
						used_plugins.insert(p->name());
						used = true;
						break;
					}
				}
			}
		}
	}

	out = sequence_to_json_array(used_plugins);
}

void falco_engine::print_stats() const
{
	std::string out;
	m_rule_stats_manager.format(m_rules, out);
	// todo(jasondellaluce): introduce a logging callback in Falco
	fprintf(stdout, "%s", out.c_str());
}

bool falco_engine::is_source_valid(const std::string &source) const
{
	return m_sources.at(source) != nullptr;
}

std::shared_ptr<sinsp_filter_factory> falco_engine::filter_factory_for_source(const std::string& source)
{
	return find_source(source)->filter_factory;
}

std::shared_ptr<sinsp_filter_factory> falco_engine::filter_factory_for_source(std::size_t source_idx)
{
	return find_source(source_idx)->filter_factory;
}

std::shared_ptr<sinsp_evt_formatter_factory> falco_engine::formatter_factory_for_source(const std::string& source)
{
	return find_source(source)->formatter_factory;
}

std::shared_ptr<sinsp_evt_formatter_factory> falco_engine::formatter_factory_for_source(std::size_t source_idx)
{
	return find_source(source_idx)->formatter_factory;
}

std::shared_ptr<filter_ruleset_factory> falco_engine::ruleset_factory_for_source(const std::string& source)
{
	return find_source(source)->ruleset_factory;
}

std::shared_ptr<filter_ruleset_factory> falco_engine::ruleset_factory_for_source(std::size_t source_idx)
{
	return find_source(source_idx)->ruleset_factory;
}

std::shared_ptr<filter_ruleset> falco_engine::ruleset_for_source(const std::string& source_name)
{
	const falco_source *source = find_source(source_name);

	return source->ruleset;
}

std::shared_ptr<filter_ruleset> falco_engine::ruleset_for_source(std::size_t source_idx)
{
	const falco_source *source = find_source(source_idx);

	return source->ruleset;
}

void falco_engine::read_file(const std::string& filename, std::string& contents)
{
	std::ifstream is;

	is.open(filename);
	if (!is.is_open())
	{
		throw falco_exception("Could not open " + filename + " for reading");
	}

	contents.assign(std::istreambuf_iterator<char>(is),
			std::istreambuf_iterator<char>());
}

static bool check_plugin_requirement_alternatives(
		const std::vector<falco_engine::plugin_version_requirement>& plugins,
		const rule_loader::plugin_version_info::requirement_alternatives& alternatives,
		std::string& err)
{
	for (const auto &req : alternatives)
	{
		for (const auto &plugin : plugins)
		{
			if (req.name == plugin.name)
			{
				sinsp_version req_version(req.version);
				sinsp_version plugin_version(plugin.version);
				if(!plugin_version.is_valid())
				{
					err = "Plugin '" + plugin.name
						+ "' has invalid version string '"
						+ plugin.version + "'";
					return false;
				}
				if (!plugin_version.compatible_with(req_version))
				{
					err = "Plugin '" + plugin.name
					+ "' version '" + plugin.version
					+ "' is not compatible with required plugin version '"
					+ req.version + "'";
					return false;
				}
				return true;
			}
		}
	}
	return false;
}

bool falco_engine::check_plugin_requirements(
		const std::vector<plugin_version_requirement>& plugins,
		std::string& err) const
{
	err = "";
	for(const auto &alternatives : m_rule_collector->required_plugin_versions())
	{
		if (!check_plugin_requirement_alternatives(plugins, alternatives, err))
		{
			if (err.empty())
			{
				for (const auto& req : alternatives)
				{
					err += err.empty() ? "" : ", ";
					err += req.name + " (>= " + req.version + ")";
				}
				err = "Plugin requirement not satisfied, must load one of: " + err;
			}
			return false;
		}
	}
	return true;
}

std::shared_ptr<filter_ruleset> falco_engine::create_ruleset(std::shared_ptr<filter_ruleset_factory> &ruleset_factory)
{
	auto ret = ruleset_factory->new_ruleset();

	ret->set_engine_state(m_engine_state);

	return ret;
}

void falco_engine::fill_engine_state_funcs(filter_ruleset::engine_state_funcs &engine_state)
{
	engine_state.get_ruleset = [this](const std::string &source_name, std::shared_ptr<filter_ruleset> &ruleset) -> bool
	{
		const falco_source *src = m_sources.at(source_name);
		if(src == nullptr)
		{
			return false;
		}

		ruleset = src->ruleset;

		return true;
	};
};

void falco_engine::complete_rule_loading() const
{
	for (const auto &src : m_sources)
	{
		src.ruleset->on_loading_complete();
	}
}

void falco_engine::set_sampling_ratio(uint32_t sampling_ratio)
{
	m_sampling_ratio = sampling_ratio;
}

void falco_engine::set_sampling_multiplier(double sampling_multiplier)
{
	m_sampling_multiplier = sampling_multiplier;
}

void falco_engine::set_extra(const std::string &extra, bool replace_container_info)
{
	m_extra = extra;
	m_replace_container_info = replace_container_info;
}

inline bool falco_engine::should_drop_evt() const
{
	if(m_sampling_multiplier == 0)
	{
		return false;
	}

	if(m_sampling_ratio == 1)
	{
		return false;
	}

	double coin = (random() * (1.0/RAND_MAX));
	return (coin >= (1.0/(m_sampling_multiplier * m_sampling_ratio)));
}
