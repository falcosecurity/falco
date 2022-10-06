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

#include <cstdlib>
#include <unistd.h>
#include <string>
#include <fstream>
#include <functional>
#include <utility>

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

using namespace std;
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
		throw falco_exception("Unknown event source index " + to_string(index));
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
					// Skip fields with the EPF_TABLE_ONLY flag.
					if(field.tags.find("EPF_TABLE_ONLY") != field.tags.end())
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

void falco_engine::load_rules(const string &rules_content, bool verbose, bool all_events)
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

std::unique_ptr<load_result> falco_engine::load_rules_file(const string &rules_filename)
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

		return std::move(res);
	}

	return load_rules(rules_content, rules_filename);
}

void falco_engine::enable_rule(const string &substring, bool enabled, const string &ruleset)
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

void falco_engine::enable_rule_exact(const string &rule_name, bool enabled, const string &ruleset)
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

void falco_engine::enable_rule_by_tag(const set<string> &tags, bool enabled, const string &ruleset)
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

std::shared_ptr<gen_event_formatter> falco_engine::create_formatter(const std::string &source,
								    const std::string &output) const
{
	return find_source(source)->formatter_factory->create_formatter(output);
}

unique_ptr<falco_engine::rule_result> falco_engine::process_event(std::size_t source_idx, gen_event *ev, uint16_t ruleset_id)
{
	// note: there are no thread-safety guarantees on the filter_ruleset::run()
	// method, but the thread-safety assumptions of falco_engine::process_event()
	// imply that concurrent invokers use different and non-switchable values of
	// source_idx, which means that at any time each filter_ruleset will only
	// be accessed by a single thread.

	const falco_source *source;

	if(source_idx == m_syscall_source_idx)
	{
		source = m_syscall_source;
	}
	else
	{
		source = find_source(source_idx);
	}

	if(should_drop_evt() || !source || !source->ruleset->run(ev, source->m_rule, ruleset_id))
	{
		return unique_ptr<struct rule_result>();
	}

	unique_ptr<struct rule_result> res(new rule_result());
	res->evt = ev;
	res->rule = source->m_rule.name;
	res->source = source->m_rule.source;
	res->format = source->m_rule.output;
	res->priority_num = source->m_rule.priority;
	res->tags = source->m_rule.tags;
	res->exception_fields = source->m_rule.exception_fields;
	m_rule_stats_manager.on_event(source->m_rule);
	return res;
}

unique_ptr<falco_engine::rule_result> falco_engine::process_event(std::size_t source_idx, gen_event *ev)
{
	return process_event(source_idx, ev, m_default_ruleset_id);
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
		m_syscall_source = find_source(m_syscall_source_idx);
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

void falco_engine::describe_rule(string *rule) const
{
	static const char* rule_fmt = "%-50s %s\n";
	fprintf(stdout, rule_fmt, "Rule", "Description");
	fprintf(stdout, rule_fmt, "----",  "-----------");
	if (!rule)
	{
		for (auto &r : m_rules)
		{
			auto str = falco::utils::wrap_text(r.description, 51, 110) + "\n";
			fprintf(stdout, rule_fmt, r.name.c_str(), str.c_str());
		}
	}
	else
	{
		auto r = m_rules.at(*rule);
		auto str = falco::utils::wrap_text(r->description, 51, 110) + "\n";
		fprintf(stdout, rule_fmt, r->name.c_str(), str.c_str());
	}
}

void falco_engine::print_stats() const
{
	string out;
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
	ifstream is;

	is.open(filename);
	if (!is.is_open())
	{
		throw falco_exception("Could not open " + filename + " for reading");
	}

	contents.assign(istreambuf_iterator<char>(is),
			istreambuf_iterator<char>());
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

void falco_engine::set_extra(string &extra, bool replace_container_info)
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
