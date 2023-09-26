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

#include <string>
#include <version.h>

#include "falco_engine.h"
#include "rule_loader_collector.h"

#define THROW(cond, err, ctx)    { if ((cond)) { throw rule_loader::rule_load_exception(falco::load_result::LOAD_ERR_VALIDATE, (err), (ctx)); } }


static inline bool is_operator_defined(const std::string& op)
{
	auto ops = libsinsp::filter::parser::supported_operators();
	return find(ops.begin(), ops.end(), op) != ops.end();
}

template <typename T>
static inline void define_info(indexed_vector<T>& infos, T& info, uint32_t id)
{
	auto prev = infos.at(info.name);
	if (prev)
	{
		info.index = prev->index;
		info.visibility = id;
		*prev = info;
	}
	else
	{
		info.index = id;
		info.visibility = id;
		infos.insert(info, info.name);
	}
}

template <typename T>
static inline void append_info(T* prev, T& info, uint32_t id)
{
	prev->visibility = id;
}

static void validate_exception_info(
	const falco_source* source,
	rule_loader::rule_exception_info &ex)
{
	if (ex.fields.is_list)
	{
		if (!ex.comps.is_valid())
		{
			ex.comps.is_list = true;
			for (size_t i = 0; i < ex.fields.items.size(); i++)
			{
				ex.comps.items.push_back(rule_loader::rule_exception_info::entry("="));
			}
		}
		THROW(ex.fields.items.size() != ex.comps.items.size(),
		       "Fields and comps lists must have equal length",
		       ex.ctx);
		for (auto &v : ex.comps.items)
		{
			THROW(!is_operator_defined(v.item),
			      std::string("'") + v.item + "' is not a supported comparison operator",
			      ex.ctx);
		}
		if (source)
		{
			for (auto &v : ex.fields.items)
			{
				THROW(!source->is_field_defined(v.item),
					std::string("'") + v.item + "' is not a supported filter field",
					ex.ctx);
			}
		}
	}
	else
	{
		if (!ex.comps.is_valid())
		{
			ex.comps.is_list = false;
			ex.comps.item = "in";
		}
		THROW(ex.comps.is_list,
		      "Fields and comps must both be strings",
		      ex.ctx);
		THROW((ex.comps.item != "in" && ex.comps.item != "pmatch" && ex.comps.item != "intersects"),
		      "When fields is a single value, comps must be one of (in, pmatch, intersects)",
		      ex.ctx);
		if (source)
		{
			THROW(!source->is_field_defined(ex.fields.item),
				std::string("'") + ex.fields.item + "' is not a supported filter field",
				ex.ctx);
		}
	}
}

void rule_loader::collector::clear()
{
	m_cur_index = 0;
	m_rule_infos.clear();
	m_list_infos.clear();
	m_macro_infos.clear();
	m_required_plugin_versions.clear();
}

const std::vector<rule_loader::plugin_version_info::requirement_alternatives>& rule_loader::collector::required_plugin_versions() const
{
	return m_required_plugin_versions;
}

const rule_loader::engine_version_info& rule_loader::collector::required_engine_version() const
{
	return m_required_engine_version;
}

const indexed_vector<rule_loader::list_info>& rule_loader::collector::lists() const
{
	return m_list_infos;
}

const indexed_vector<rule_loader::macro_info>& rule_loader::collector::macros() const
{
	return m_macro_infos;
}

const indexed_vector<rule_loader::rule_info>& rule_loader::collector::rules() const
{
	return m_rule_infos;
}

void rule_loader::collector::define(configuration& cfg, engine_version_info& info)
{
	auto engine_version = sinsp_version(falco_engine::engine_version());
	sinsp_version required_engine_version(info.version);
	THROW(!required_engine_version.m_valid, "Unable to parse " + info.version
		  + " as a semver string. Expected \"x.y.z\" semver format.", info.ctx);

	THROW(!engine_version.check(required_engine_version), "Rules require engine version "
		  + required_engine_version.as_string() + " but engine version is "
		  + engine_version.as_string(), info.ctx);

	sinsp_version current_required_engine_version(m_required_engine_version.version);

	// Store max required_engine_version
	if(current_required_engine_version.check(required_engine_version))
	{
		m_required_engine_version = info;
	}
}

void rule_loader::collector::define(configuration& cfg, plugin_version_info& info)
{
	std::unordered_set<std::string> plugin_names;
	for (const auto& req : info.alternatives)
	{
		sinsp_version plugin_version(req.version);
		THROW(!plugin_version.m_valid,
			"Invalid required version '" + req.version
				+ "' for plugin '" + req.name + "'",
			info.ctx);
		THROW(plugin_names.find(req.name) != plugin_names.end(),
			"Defined multiple alternative version requirements for plugin '"
				+ req.name + "'",
			info.ctx);
		plugin_names.insert(req.name);
	}
	m_required_plugin_versions.push_back(info.alternatives);
}

void rule_loader::collector::define(configuration& cfg, list_info& info)
{
	define_info(m_list_infos, info, m_cur_index++);
}

void rule_loader::collector::append(configuration& cfg, list_info& info)
{
	auto prev = m_list_infos.at(info.name);
	THROW(!prev,
	       "List has 'append' key but no list by that name already exists",
	       info.ctx);
	prev->items.insert(prev->items.end(), info.items.begin(), info.items.end());
	append_info(prev, info, m_cur_index++);
}

void rule_loader::collector::define(configuration& cfg, macro_info& info)
{
	define_info(m_macro_infos, info, m_cur_index++);
}

void rule_loader::collector::append(configuration& cfg, macro_info& info)
{
	auto prev = m_macro_infos.at(info.name);
	THROW(!prev,
	       "Macro has 'append' key but no macro by that name already exists",
	       info.ctx);
	prev->cond += " ";
	prev->cond += info.cond;
	append_info(prev, info, m_cur_index++);
}

void rule_loader::collector::define(configuration& cfg, rule_info& info)
{
	auto prev = m_rule_infos.at(info.name);
	THROW(prev && prev->source != info.source,
		"Rule has been re-defined with a different source",
		info.ctx);

	auto source = cfg.sources.at(info.source);
	if (!source)
	{
		info.unknown_source = true;
		cfg.res->add_warning(falco::load_result::LOAD_UNKNOWN_SOURCE,
				     "Unknown source " + info.source + ", skipping",
				     info.ctx);
	}
	for (auto &ex : info.exceptions)
	{
		THROW(!ex.fields.is_valid(),
			"Rule exception item must have fields property with a list of fields",
			ex.ctx);
		validate_exception_info(source, ex);
	}

	define_info(m_rule_infos, info, m_cur_index++);
}

void rule_loader::collector::append(configuration& cfg, rule_info& info)
{
	auto prev = m_rule_infos.at(info.name);

	THROW(!prev,
	       "Rule has 'append' key but no rule by that name already exists",
	       info.ctx);
	THROW(info.cond.empty() && info.exceptions.empty(),
	       "Appended rule must have exceptions or condition property",
	       info.ctx);

	// note: source can be nullptr in case we've collected a
	// rule for which the source is unknown
	falco_source* source = nullptr;
	if (!prev->unknown_source)
	{
		// note: if the source is not unknown, this should not return nullptr
		source = cfg.sources.at(prev->source);
		THROW(!source,
	    	std::string("Unknown source ") + prev->source,
	    	info.ctx);
	}

	if (!info.cond.empty())
	{
		prev->cond += " ";
		prev->cond += info.cond;
	}

	for (auto &ex : info.exceptions)
	{
		auto prev_ex = find_if(prev->exceptions.begin(), prev->exceptions.end(),
			[&ex](const rule_loader::rule_exception_info& i)
				{ return i.name == ex.name; });
		if (prev_ex == prev->exceptions.end())
		{
			THROW(!ex.fields.is_valid(),
			       "Rule exception must have fields property with a list of fields",
			       ex.ctx);
			THROW(ex.values.empty(),
			       "Rule exception must have values property with a list of values",
			       ex.ctx);
			validate_exception_info(source, ex);
			prev->exceptions.push_back(ex);
		}
		else
		{
			THROW(ex.fields.is_valid(),
			       "Can not append exception fields to existing exception, only values",
			       ex.ctx);
			THROW(ex.comps.is_valid(),
			       "Can not append exception comps to existing exception, only values",
			       ex.ctx);
			prev_ex->values.insert(
				prev_ex->values.end(), ex.values.begin(), ex.values.end());
		}
	}
	append_info(prev, info, m_cur_index++);
}

void rule_loader::collector::enable(configuration& cfg, rule_info& info)
{
	auto prev = m_rule_infos.at(info.name);
	THROW(!prev,
	       "Rule has 'enabled' key but no rule by that name already exists",
	       info.ctx);
	prev->enabled = info.enabled;
}
