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
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <sinsp.h>
#include <plugin.h>

#include "falco_engine.h"
#include "falco_utils.h"
#include "falco_engine_version.h"
#include "rule_loader_reader.h"
#include "rule_loader_compiler.h"

#include "formats.h"

#include "utils.h"
#include "banned.h" // This raises a compilation error when certain functions are used
#include "evttype_index_ruleset.h"

const std::string falco_engine::s_default_ruleset = "falco-default-ruleset";

using namespace falco;

falco_engine::falco_engine(bool seed_rng)
	: m_syscall_source(NULL),
	  m_syscall_source_idx(SIZE_MAX),
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
}

falco_engine::~falco_engine()
{
	m_rules.clear();
	m_rule_collector.clear();
	m_rule_stats_manager.clear();
	m_sources.clear();
}

uint32_t falco_engine::engine_version()
{
	return (uint32_t) FALCO_ENGINE_VERSION;
}

const falco_source* falco_engine::find_source(const std::string& name) const
{
	auto ret = m_sources.at(name);
	if(!ret)
	{
		throw falco_exception("Unknown event source " + name);
	}
	return ret;
}

const falco_source* falco_engine::find_source(std::size_t index) const
{
	auto ret = m_sources.at(index);
	if(!ret)
	{
		throw falco_exception("Unknown event source index " + std::to_string(index));
	}
	return ret;
}

// Return a key that uniquely represents a field class.
// For now, we assume name + shortdesc is unique.
static std::string fieldclass_key(const gen_event_filter_factory::filter_fieldclass_info &fld_info)
{
	return fld_info.name + fld_info.shortdesc;
}

void falco_engine::list_fields(std::string &source, bool verbose, bool names_only, bool markdown) const
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

void falco_engine::load_rules(const std::string &rules_content, bool verbose, bool all_events)
{
	static const std::string no_name = "N/A";

	std::unique_ptr<load_result> res = load_rules(rules_content, no_name);

	interpret_load_result(res, no_name, rules_content, verbose);
}

std::unique_ptr<load_result> falco_engine::load_rules(const std::string &rules_content, const std::string &name)
{
	rule_loader::configuration cfg(rules_content, m_sources, name);
	cfg.min_priority = m_min_priority;
	cfg.output_extra = m_extra;
	cfg.replace_output_container_info = m_replace_container_info;
	cfg.default_ruleset_id = m_default_ruleset_id;

	rule_loader::reader reader;
	if (reader.read(cfg, m_rule_collector))
	{
		for (auto &src : m_sources)
		{
			src.ruleset = src.ruleset_factory->new_ruleset();
		}

		rule_loader::compiler compiler;
		m_rules.clear();
		compiler.compile(cfg, m_rule_collector, m_rules);
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

void falco_engine::load_rules_file(const std::string &rules_filename, bool verbose, bool all_events)
{
	std::string rules_content;

	read_file(rules_filename, rules_content);

	std::unique_ptr<load_result> res = load_rules(rules_content, rules_filename);

	interpret_load_result(res, rules_filename, rules_content, verbose);
}

std::unique_ptr<load_result> falco_engine::load_rules_file(const std::string &rules_filename)
{
	std::string rules_content;

	try {
		read_file(rules_filename, rules_content);
	}
	catch (falco_exception &e)
	{
		rule_loader::context ctx(rules_filename);

		std::unique_ptr<rule_loader::result> res(new rule_loader::result(rules_filename));

		res->add_error(load_result::LOAD_ERR_FILE_READ, e.what(), ctx);

// Old gcc versions (e.g. 4.8.3) won't allow move elision but newer versions
// (e.g. 10.2.1) would complain about the redundant move.
#if __GNUC__ > 4
		return res;
#else
		return std::move(res);
#endif
	}

	return load_rules(rules_content, rules_filename);
}

void falco_engine::enable_rule(const std::string &substring, bool enabled, const std::string &ruleset)
{
	uint16_t ruleset_id = find_ruleset_id(ruleset);
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

void falco_engine::evttypes_for_ruleset(std::string &source, std::set<uint16_t> &evttypes, const std::string &ruleset)
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

std::shared_ptr<gen_event_formatter> falco_engine::create_formatter(const std::string &source,
								    const std::string &output) const
{
	return find_source(source)->formatter_factory->create_formatter(output);
}

std::unique_ptr<std::vector<falco_engine::rule_result>> falco_engine::process_event(std::size_t source_idx,
	gen_event *ev, uint16_t ruleset_id, falco_common::rule_matching strategy)
{
	// note: there are no thread-safety guarantees on the filter_ruleset::run()
	// method, but the thread-safety assumptions of falco_engine::process_event()
	// imply that concurrent invokers use different and non-switchable values of
	// source_idx, which means that at any time each filter_ruleset will only
	// be accessed by a single thread.

	const falco_source *source;

	if(source_idx == m_syscall_source_idx)
	{
		if(m_syscall_source == NULL)
		{
			m_syscall_source = find_source(m_syscall_source_idx);
		}

		source = m_syscall_source;
	}
	else
	{
		source = find_source(source_idx);
	}

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
	for(auto rule : source->m_rules)
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
	gen_event *ev, falco_common::rule_matching strategy)
{
	return process_event(source_idx, ev, m_default_ruleset_id, strategy);
}

std::size_t falco_engine::add_source(const std::string &source,
				     std::shared_ptr<gen_event_filter_factory> filter_factory,
				     std::shared_ptr<gen_event_formatter_factory> formatter_factory)
{
	// evttype_index_ruleset is the default ruleset implementation
	std::shared_ptr<filter_ruleset_factory> ruleset_factory(
		new evttype_index_ruleset_factory(filter_factory));
	size_t idx = add_source(source, filter_factory, formatter_factory, ruleset_factory);

	if(source == falco_common::syscall_source)
	{
		m_syscall_source_idx = idx;
	}

	return idx;
}

std::size_t falco_engine::add_source(const std::string &source,
	std::shared_ptr<gen_event_filter_factory> filter_factory,
	std::shared_ptr<gen_event_formatter_factory> formatter_factory,
	std::shared_ptr<filter_ruleset_factory> ruleset_factory)
{
	falco_source src;
	src.name = source;
	src.filter_factory = filter_factory;
	src.formatter_factory = formatter_factory;
	src.ruleset_factory = ruleset_factory;
	src.ruleset = ruleset_factory->new_ruleset();
	return m_sources.insert(src, source);
}

void falco_engine::describe_rule(std::string *rule, const std::vector<std::shared_ptr<sinsp_plugin>>& plugins, bool json) const
{
	if(!json)
	{
		static const char *rule_fmt = "%-50s %s\n";
		fprintf(stdout, rule_fmt, "Rule", "Description");
		fprintf(stdout, rule_fmt, "----", "-----------");
		if(!rule)
		{
			for(auto &r : m_rules)
			{
				auto str = falco::utils::wrap_text(r.description, 51, 110) + "\n";
				fprintf(stdout, rule_fmt, r.name.c_str(), str.c_str());
			}
		}
		else
		{
			auto r = m_rules.at(*rule);
			if(r == nullptr)
			{
				return;
			}
			auto str = falco::utils::wrap_text(r->description, 51, 110) + "\n";
			fprintf(stdout, rule_fmt, r->name.c_str(), str.c_str());
		}

		return;
	}

	Json::FastWriter writer;
	std::string json_str;

	if(!rule)
	{
		// In this case we build json information about
		// all rules, macros and lists
		Json::Value output;

		// Store required engine version
		auto required_engine_version = m_rule_collector.required_engine_version();
		output["required_engine_version"] = std::to_string(required_engine_version.version);

		// Store required plugin versions
		Json::Value plugin_versions = Json::arrayValue;
		auto required_plugin_versions = m_rule_collector.required_plugin_versions();
		for(const auto& req : required_plugin_versions)
		{
			Json::Value r;
			r["name"] = req.at(0).name;
			r["version"] = req.at(0).version;

			Json::Value alternatives = Json::arrayValue;
			for(size_t i = 1; i < req.size(); i++)
			{
				Json::Value alternative;
				alternative["name"] = req[i].name;
				alternative["version"] = req[i].version;
				alternatives.append(alternative);
			}
			r["alternatives"] = alternatives;
			
			plugin_versions.append(r);
		}
		output["required_plugin_versions"] = plugin_versions;

		// Store information about rules
		Json::Value rules_array = Json::arrayValue;
		for(const auto& r : m_rules)
		{
			auto ri = m_rule_collector.rules().at(r.name);
			Json::Value rule;
			get_json_details(rule, r, *ri, plugins);

			// Append to rule array
			rules_array.append(rule);
		}
		output["rules"] = rules_array;
		
		// Store information about macros
		Json::Value macros_array = Json::arrayValue;
		for(const auto &m : m_rule_collector.macros())
		{
			Json::Value macro;
			get_json_details(macro, m);
			macros_array.append(macro);
		}
		output["macros"] = macros_array;

		// Store information about lists 
		Json::Value lists_array = Json::arrayValue;
		for(const auto &l : m_rule_collector.lists())
		{
			Json::Value list;
			get_json_details(list, l);
			lists_array.append(list);			
		}
		output["lists"] = lists_array;

		json_str = writer.write(output);
	}
	else
	{
		// build json information for just the specified rule
		auto ri = m_rule_collector.rules().at(*rule);
		if(ri == nullptr || ri->unknown_source)
		{
			throw falco_exception("Rule \"" + *rule + "\" is not loaded");
		}
		auto r = m_rules.at(ri->name);
		Json::Value rule; 
		get_json_details(rule, *r, *ri, plugins);
		json_str = writer.write(rule);
	}

	fprintf(stdout, "%s", json_str.c_str());
}

void falco_engine::get_json_details(
	Json::Value &out,
	const falco_rule &r,
	const rule_loader::rule_info &ri,
	const std::vector<std::shared_ptr<sinsp_plugin>>& plugins) const
{
	Json::Value rule_info;

	// Fill general rule information
	rule_info["name"] = r.name;
	rule_info["condition"] = ri.cond;
	rule_info["priority"] = format_priority(r.priority, false);
	rule_info["output"] = r.output;
	rule_info["description"] = r.description;
	rule_info["enabled"] = ri.enabled;
	rule_info["source"] = r.source;
	Json::Value tags = Json::arrayValue;
	for(const auto &t : ri.tags)
	{
		tags.append(t);
	}
	rule_info["tags"] = tags;
	out["info"] = rule_info;

	// Parse rule condition and build the AST
	// Assumption: no exception because rules have already been loaded.
	auto ast = libsinsp::filter::parser(ri.cond).parse();

	// get details related to the condition's filter
	filter_details details;
	Json::Value json_details;
	for(const auto &m : m_rule_collector.macros())
	{
		details.known_macros.insert(m.name);
	}
	for(const auto &l : m_rule_collector.lists())
	{
		details.known_lists.insert(l.name);
	}
	filter_details_resolver().run(ast.get(), details);
	get_json_filter_details(json_details, details);
	out["details"] = json_details;

	// Get fields from output string
	auto fmt = create_formatter(r.source, r.output);
	std::vector<std::string> out_fields;
	fmt->get_field_names(out_fields);
	Json::Value outputFields = Json::arrayValue;
	for(const auto &of : out_fields)
	{
		outputFields.append(of);
	}
	out["details"]["output_fields"] = outputFields;

	// Get fields from exceptions
	Json::Value exception_fields = Json::arrayValue;
	for(const auto &f : r.exception_fields)
	{
		exception_fields.append(f);
	}
	out["details"]["exception_fields"] = exception_fields;

	// Get names and operators from exceptions
	Json::Value exception_names = Json::arrayValue;
	Json::Value exception_operators = Json::arrayValue;
	for(const auto &e : ri.exceptions)
	{
		exception_names.append(e.name);
		if(e.comps.is_list)
		{
			for(const auto& c : e.comps.items)
			{
				if(c.is_list)
				{
					// considering max two levels of lists
					for(const auto& i : c.items)
					{
						exception_operators.append(i.item);
					}
				}
				else
				{
					exception_operators.append(c.item);
				}
			}
		}
		else
		{
			exception_operators.append(e.comps.item);
		}	
	}
	out["details"]["exceptions"] = exception_names;
	out["details"]["exception_operators"] = exception_operators;

	// Store event types
	Json::Value events;
	get_json_evt_types(events, ri.source, details);
	out["details"]["events"] = events;

	// Compute the plugins that are actually used by this rule. This is involves:
	// - The rule's event source, that can be implemented by a plugin
	// - The fields used in the rule's condition, output, and exceptions
	// - The evt types used in the rule's condition checks, that can potentially
	//   match plugin-provided async events
	Json::Value used_plugins;
	// note: making a union of conditions's and output's fields
	// note: the condition's AST should include all resolved refs and exceptions
	details.fields.insert(out_fields.begin(), out_fields.end());
	get_json_used_plugins(used_plugins, ri.source, details.evtnames, details.fields, plugins);
	out["details"]["plugins"] = used_plugins;
}

void falco_engine::get_json_details(
	Json::Value& out,
	const rule_loader::macro_info& m) const
{
	Json::Value macro_info;

	macro_info["name"] = m.name;
	macro_info["condition"] = m.cond;
	out["info"] = macro_info;

	// Parse rule condition and build the AST
	// Assumption: no exception because rules have already been loaded.
	auto ast = libsinsp::filter::parser(m.cond).parse();

	// get details related to the condition's filter
	filter_details details;
	Json::Value json_details;
	for(const auto &m : m_rule_collector.macros())
	{
		details.known_macros.insert(m.name);
	}
	for(const auto &l : m_rule_collector.lists())
	{
		details.known_lists.insert(l.name);
	}
	filter_details_resolver().run(ast.get(), details);
	get_json_filter_details(json_details, details);
	out["details"] = json_details;

	// Store event types
	Json::Value events;
	get_json_evt_types(events, "", details);
	out["details"]["events"] = events;
}

void falco_engine::get_json_details(
	Json::Value& out,
	const rule_loader::list_info& l) const
{
	Json::Value list_info;
	list_info["name"] = l.name;

	Json::Value items = Json::arrayValue;
	Json::Value lists = Json::arrayValue;
	for(const auto &i : l.items)
	{
		if(m_rule_collector.lists().at(i) != nullptr)
		{
			lists.append(i);
			continue;
		}
		items.append(i);
	}

	list_info["items"] = items;
	out["info"] = list_info;
	out["details"]["lists"] = lists;
}

void falco_engine::get_json_filter_details(
	Json::Value& out,
	const filter_details& details) const
{
	Json::Value macros = Json::arrayValue;
	for(const auto &m : details.macros)
	{
		macros.append(m);
	}
	out["macros"] = macros;

	Json::Value operators = Json::arrayValue;
	for(const auto &o : details.operators)
	{
		operators.append(o);
	}
	out["operators"] = operators;

	Json::Value condition_fields = Json::arrayValue;
	for(const auto &f : details.fields)
	{
		condition_fields.append(f);
	}
	out["condition_fields"] = condition_fields;

	Json::Value lists = Json::arrayValue;
	for(const auto &l : details.lists)
	{
		lists.append(l);
	}
	out["lists"] = lists;
}

void falco_engine::get_json_evt_types(
	Json::Value& out,
	const std::string& source,
	const filter_details& details) const
{
	out = Json::arrayValue;
	for (const auto& n : details.evtnames)
	{
		out.append(n);
	}

	// plugin-implemented sources always match pluginevent.
	// note: macros have no source and can potentially be referenced in a rule
	// used for a plugin-implemented source.
	if(source.empty() || source != falco_common::syscall_source)
	{
		for (const auto& n : libsinsp::events::event_set_to_names({PPME_PLUGINEVENT_E}, false))
		{
			out.append(n);
		}
	}
}

void falco_engine::get_json_used_plugins(
	Json::Value& out,
	const std::string& source,
	const std::unordered_set<std::string>& evtnames,
	const std::unordered_set<std::string>& fields,
	const std::vector<std::shared_ptr<sinsp_plugin>>& plugins) const
{
	out = Json::arrayValue;	
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
				out.append(p->name());
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
					if (!used && fields.find(f.m_name) != fields.end())
					{
						out.append(p->name());
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
						out.append(p->name());
						used = true;
						break;
					}
				}
			}
		}
	}
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

void falco_engine::interpret_load_result(std::unique_ptr<load_result>& res,
					 const std::string& rules_filename,
					 const std::string& rules_content,
					 bool verbose)
{
	falco::load_result::rules_contents_t rc = {{rules_filename, rules_content}};

	if(!res->successful())
	{
		// The output here is always the full e.g. "verbose" output.
		throw falco_exception(res->as_string(true, rc).c_str());
	}

	if(verbose && res->has_warnings())
	{
		// Here, verbose controls whether to additionally
		// "log" e.g. print to stderr. What's logged is always
		// non-verbose so it fits on a single line.
		// todo(jasondellaluce): introduce a logging callback in Falco
		fprintf(stderr, "%s\n", res->as_string(false, rc).c_str());
	}
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
				if(!plugin_version.m_valid)
				{
					err = "Plugin '" + plugin.name
						+ "' has invalid version string '"
						+ plugin.version + "'";
					return false;
				}
				if (!plugin_version.check(req_version))
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
	for (const auto &alternatives : m_rule_collector.required_plugin_versions())
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

void falco_engine::set_extra(std::string &extra, bool replace_container_info)
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
