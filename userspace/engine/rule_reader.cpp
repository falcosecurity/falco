/*
Copyright (C) 2022 The Falco Authors.

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

#include "rule_reader.h"

#define THROW(cond, err)    { if (cond) { throw falco_exception(err); } }

static rule_loader::context yaml_get_context(
		const string& content,
		const vector<YAML::Node>& docs,
		vector<YAML::Node>::iterator doc,
		YAML::iterator node)
{
	rule_loader::context m;
	YAML::Node item = *node++;
	YAML::Node cur_doc = *doc++;
	// include the "- " sequence mark
	size_t from = item.Mark().pos - 2;
	size_t to = 0;
	if (node != cur_doc.end())
	{
		// end of item is beginning of next item
		to = node->Mark().pos - 2;
	}
	else if (doc != docs.end())
	{
		// end of item is beginning of next doc
		to = doc->Mark().pos - 4;
	}
	else
	{
		// end of item is end of file contents
		to = content.length();
	}
	m.content = content.substr(from, to - from);
	m.content = trim(m.content);
	return m;
}

template <typename T>
static bool decode_val(const YAML::Node& v, T& out)
{
	return v.IsDefined() && v.IsScalar() && YAML::convert<T>::decode(v, out);
}

template <typename T>
static bool decode_seq(const YAML::Node& item, vector<T>& out)
{
	if (item.IsDefined() && item.IsSequence())
	{
		T value;
		for(const YAML::Node& v : item)
		{
			THROW(!v.IsScalar() || !YAML::convert<T>::decode(v, value),
				"Can't decode YAML sequence value: " + YAML::Dump(v));
			out.push_back(value);
		}
		return true;
	}
	return false;
}

template <typename T>
static bool decode_seq(const YAML::Node& item, set<T>& out)
{
	if (item.IsDefined() && item.IsSequence())
	{
		T value;
		for(const YAML::Node& v : item)
		{
			THROW(!v.IsScalar() || !YAML::convert<T>::decode(v, value),
				"Can't decode YAML sequence value: " + YAML::Dump(v));
			out.insert(value);
		}
		return true;
	}
	return false;
}

static bool decode_exception_info_entry(
	const YAML::Node& item,
	rule_loader::rule_exception_info::entry& out)
{
	if (item.IsDefined())
	{
		if (item.IsScalar())
		{
			out.is_list = false;
			if (YAML::convert<string>::decode(item, out.item))
			{
				return true;
			}
		}
		if (item.IsSequence())
		{
			out.is_list = true;
			rule_loader::rule_exception_info::entry tmp;
			for(const YAML::Node& v : item)
			{
				if (!decode_exception_info_entry(v, tmp))
				{
					return false;
				}
				out.items.push_back(tmp);
			}
			return true;
		}
	}
	return false;
}

static void read_rule_exceptions(
	const YAML::Node& item,
	rule_loader::rule_info& v)
{
	THROW(!item.IsSequence(), "Rule exceptions must be a sequence");
	for (auto &ex : item)
	{
		rule_loader::rule_exception_info v_ex;
		THROW(!decode_val(ex["name"], v_ex.name) || v_ex.name.empty(),
			"Rule exception item must have name property");
		// note: the legacy lua loader used to throw a "xxx must strings" error
		decode_exception_info_entry(ex["fields"], v_ex.fields);
		decode_exception_info_entry(ex["comps"], v_ex.comps);
		if (ex["values"].IsDefined())
		{
			THROW(!ex["values"].IsSequence(),
				"Rule exception values must be a sequence");
			for (auto &val : ex["values"])
			{
				rule_loader::rule_exception_info::entry v_ex_val;
				decode_exception_info_entry(val, v_ex_val);
				v_ex.values.push_back(v_ex_val);
			}
		}
		v.exceptions.push_back(v_ex);
	}
}

static void read_item(
		rule_loader::configuration& cfg,
		rule_loader& loader,
		const YAML::Node& item,
		const rule_loader::context& ctx)
{
	if (item["required_engine_version"].IsDefined())
	{
		rule_loader::engine_version_info v;
		THROW(!decode_val(item["required_engine_version"], v.version),
			"Value of required_engine_version must be a number");
		loader.define(cfg, v);
	}
	else if(item["required_plugin_versions"].IsDefined())
	{
		THROW(!item["required_plugin_versions"].IsSequence(),
			"Value of required_plugin_versions must be a sequence");

		for(const YAML::Node& plugin : item["required_plugin_versions"])
		{
			rule_loader::plugin_version_info v;
			THROW(!decode_val(plugin["name"], v.name) || v.name.empty(),
				"required_plugin_versions item must have name property");
			THROW(!decode_val(plugin["version"], v.version) || v.version.empty(),
				"required_plugin_versions item must have version property");
			loader.define(cfg, v);
		}
	}
	else if(item["list"].IsDefined())
	{
		rule_loader::list_info v;
		v.ctx = ctx;
		bool append = false;
		THROW(!decode_val(item["list"], v.name) || v.name.empty(),
			"List name is empty");
		THROW(!decode_seq(item["items"], v.items),
			"List must have property items");
		if(decode_val(item["append"], append) && append)
		{
			loader.append(cfg, v);
		}
		else
		{
			loader.define(cfg, v);
		}
	}
	else if(item["macro"].IsDefined())
	{
		rule_loader::macro_info v;
		v.ctx = ctx;
		bool append = false;
		v.source = falco_common::syscall_source;
		THROW(!decode_val(item["macro"], v.name) || v.name.empty(),
			"Macro name is empty");
		THROW(!decode_val(item["condition"], v.cond) || v.cond.empty(),
			"Macro must have property condition");
		decode_val(item["source"], v.source);
		if(decode_val(item["append"], append) && append)
		{
			loader.append(cfg, v);
		}
		else
		{
			loader.define(cfg, v);
		}
	}
	else if(item["rule"].IsDefined())
	{
		rule_loader::rule_info v;
		v.ctx = ctx;
		bool append = false;
		v.enabled = true;
		v.warn_evttypes = true;
		v.skip_if_unknown_filter = false;
		THROW(!decode_val(item["rule"], v.name) || v.name.empty(),
			"Rule name is empty");
		if(decode_val(item["append"], append) && append)
		{
			decode_val(item["condition"], v.cond);
			if (item["exceptions"].IsDefined())
			{
				read_rule_exceptions(item["exceptions"], v);
			}
			loader.append(cfg, v);
		}
		else
		{
			string priority;
			bool has_enabled = decode_val(item["enabled"], v.enabled);
			bool has_defs = decode_val(item["condition"], v.cond)
					&& decode_val(item["output"], v.output)
					&& decode_val(item["desc"], v.desc)
					&& decode_val(item["priority"], priority);
			if (!has_defs)
			{
				THROW(!has_enabled, "Rule must have properties 'condition', 'output', 'desc', and 'priority'");
				loader.enable(cfg, v);
			}
			else
			{
				v.output = trim(v.output);
				v.source = falco_common::syscall_source;
				THROW(!falco_common::parse_priority(priority, v.priority),
					"Invalid priority");
				decode_val(item["source"], v.source);
				decode_val(item["warn_evttypes"], v.warn_evttypes);
				decode_val(item["skip-if-unknown-filter"], v.skip_if_unknown_filter);
				decode_seq(item["tags"], v.tags);
				if (item["exceptions"].IsDefined())
				{
					read_rule_exceptions(item["exceptions"], v);
				}
				loader.define(cfg, v);
			}
		}
	}
	else
	{
		cfg.warnings.push_back("Unknown top level object");
	}
}

bool rule_reader::load(rule_loader::configuration& cfg, rule_loader& loader)
{
	std::vector<YAML::Node> docs;
	try
	{
		docs = YAML::LoadAll(cfg.content);
	}
	catch(const exception& e)
	{
		cfg.errors.push_back("Could not load YAML file: " + string(e.what()));
		return false;
	}
	
	for (auto doc = docs.begin(); doc != docs.end(); doc++)
	{
		if (doc->IsDefined() && !doc->IsNull())
		{
			if(!doc->IsMap() && !doc->IsSequence())
			{
				cfg.errors.push_back("Rules content is not yaml");
				return false;
			}
			if(!doc->IsSequence())
			{
				cfg.errors.push_back(
					"Rules content is not yaml array of objects");
				return false;
			}
			for (auto it = doc->begin(); it != doc->end(); it++)
			{
				if (!it->IsNull())
				{
					auto ctx = yaml_get_context(cfg.content, docs, doc, it);
					YAML::Node item = *it;
					try
					{
						THROW(!item.IsMap(), "Unexpected element type. "
							"Each element should be a yaml associative array.");
						read_item(cfg, loader, item, ctx);
					}
					catch(const exception& e)
					{
						cfg.errors.push_back(ctx.error(e.what()));
						return false;
					}
				}
			}
		}
	}
	return true;
}
