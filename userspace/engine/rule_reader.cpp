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

#define THROW(cond, err, ctx)    { if ((cond)) { throw rule_loader::rule_load_exception(load_result::LOAD_ERR_YAML_VALIDATE, (err), (ctx)); } }

using namespace falco;

// Don't call this directly, call decode_val/decode_optional_val instead.
template <typename T>
static void decode_val_generic(const YAML::Node& item, const char *key, T& out, const rule_loader::context& ctx, bool optional)
{
	const YAML::Node& val = item[key];

	if(!val.IsDefined() && optional)
	{
		return;
	}

	THROW(!val.IsDefined(), std::string("Item has no mapping for key '") + key + "'", ctx);
	THROW(val.IsNull(), std::string("Mapping for key '") + key + "' is empty", ctx);

	rule_loader::context valctx(val, "value for", key, ctx);
	THROW(!val.IsScalar(), "Value is not a scalar value", valctx);
	THROW(val.Scalar().empty(), "Value must be non-empty", valctx);

	THROW(!YAML::convert<T>::decode(val, out), "Can't decode YAML scalar value", valctx);
}

template <typename T>
static void decode_val(const YAML::Node& item, const char *key, T& out, const rule_loader::context& ctx)
{
	bool optional = false;

	decode_val_generic(item, key, out, ctx, optional);
}

template <typename T>
static void decode_optional_val(const YAML::Node& item, const char *key, T& out, const rule_loader::context& ctx)
{
	bool optional = true;

	decode_val_generic(item, key, out, ctx, optional);
}

// Don't call this directly, call decode_items/decode_tags instead.
template <typename T>
static void decode_seq(const YAML::Node& item, const char *key,
		       std::function<void(T)> inserter,
		       const rule_loader::context &ctx, bool optional)
{
	const YAML::Node& val = item[key];

	if(!val.IsDefined() && optional)
	{
		return;
	}

	THROW(!val.IsDefined(), std::string("Item has no mapping for key '") + key + "'", ctx);

	rule_loader::context valctx(val, "value for", key, ctx);
	THROW(!val.IsSequence(), "Value is not a sequence", valctx);

	T value;
	for(const YAML::Node& v : val)
	{
		rule_loader::context ictx(v, "list item", "", valctx);
		THROW(!v.IsScalar(), "sequence value is not scalar", ictx);
		THROW(!YAML::convert<T>::decode(v, value), "Can't decode YAML sequence value", ictx);
		inserter(value);
	}
}

template <typename T>
static void decode_items(const YAML::Node& item, vector<T>& out,
		       const rule_loader::context& ctx)
{
	bool optional = false;

	std::function<void(T)> inserter = [&out] (T value) {
		out.push_back(value);
	};

	decode_seq(item, "items", inserter, ctx, optional);
}

template <typename T>
static void decode_tags(const YAML::Node& item, set<T>& out,
		       const rule_loader::context& ctx)
{
	bool optional = true;

	std::function<void(T)> inserter = [&out] (T value) {
		out.insert(value);
	};

	decode_seq(item, "tags", inserter, ctx, optional);
}

// Don't call this directly, call decode_exception_{fields,comps,values} instead
static void decode_exception_info_entry(
	const YAML::Node& item,
	const char *key,
	rule_loader::rule_exception_info::entry& out,
	const rule_loader::context& ctx,
	bool optional)
{
	const YAML::Node& val = (key == NULL ? item : item[key]);

	if(!val.IsDefined() && optional)
	{
		return;
	}

	THROW(!val.IsDefined(), std::string("Item has no mapping for key '") + key + "'", ctx);

	rule_loader::context valctx(val, "value for", (key == NULL ? "" : key), ctx);

	if (val.IsScalar())
	{
		THROW(val.Scalar().empty(), "Value must be non-empty", valctx);
		out.is_list = false;
		THROW(!YAML::convert<string>::decode(val, out.item), "Could not decode scalar value", valctx);
	}
	if (val.IsSequence())
	{
		out.is_list = true;
		rule_loader::rule_exception_info::entry tmp;
		for(const YAML::Node& v : val)
		{
			rule_loader::context lctx(v, "list exception entry", "", valctx);

			// Optional is always false once you get past the outer values
			optional = false;
			decode_exception_info_entry(v, NULL, tmp, lctx, optional);
			out.items.push_back(tmp);
		}
	}
}

static void decode_exception_fields(
	const YAML::Node& item,
	rule_loader::rule_exception_info::entry& out,
	const rule_loader::context& ctx,
	bool optional)
{
	decode_exception_info_entry(item, "fields", out, ctx, optional);
}

static void decode_exception_comps(
	const YAML::Node& item,
	rule_loader::rule_exception_info::entry& out,
	const rule_loader::context& ctx)
{
	bool optional = true;

	decode_exception_info_entry(item, "comps", out, ctx, optional);
}

static void decode_exception_values(
	const YAML::Node& item,
	rule_loader::rule_exception_info::entry& out,
	const rule_loader::context& ctx)
{
	bool optional = false;

	decode_exception_info_entry(item, NULL, out, ctx, optional);
}

static void read_rule_exceptions(
	const YAML::Node& item,
	rule_loader::rule_info& v,
	const rule_loader::context& parent,
	bool append)
{
	const YAML::Node& exs = item["exceptions"];

	// No exceptions property, or an exceptions property with
	// nothing in it, are allowed
	if(!exs.IsDefined() || exs.IsNull())
	{
		return;
	}

	rule_loader::context exes_ctx(exs, "exceptions", "", parent);

	THROW(!exs.IsSequence(), "Rule exceptions must be a sequence", exes_ctx);

	for (auto &ex : exs)
	{
		// Make a temp context to verify simple properties
		// about the exception.
		std::string name;
		rule_loader::context tmp(ex, "exception", "", exes_ctx);

		THROW(!ex.IsMap(), "Rule exception must be a mapping", tmp);
		decode_val(ex, "name", name, tmp);

		// Now use a real context including the exception name.
		rule_loader::context ex_ctx(ex, "exception", name, parent);
		rule_loader::rule_exception_info v_ex(ex_ctx);
		v_ex.name = name;

		// note: the legacy lua loader used to throw a "xxx must strings" error

		// fields are optional when append is true
		decode_exception_fields(ex, v_ex.fields, ex_ctx, append);
		decode_exception_comps(ex, v_ex.comps, ex_ctx);
		const YAML::Node& exvals = ex["values"];
		if (exvals.IsDefined())
		{
			rule_loader::context vals_ctx(exvals, "exception values", "", ex_ctx);
			THROW(!exvals.IsSequence(),
			       "Rule exception values must be a sequence", vals_ctx);
			for (auto &val : exvals)
			{
				rule_loader::context vctx(val, "exception value", "", vals_ctx);
				rule_loader::rule_exception_info::entry v_ex_val;

				decode_exception_values(val, v_ex_val, vctx);
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
	const rule_loader::context& parent)
{
	rule_loader::context tmp(item, "item", "", parent);
	THROW(!item.IsMap(), "Unexpected element type. "
	      "Each element should be a yaml associative array.", tmp);

	if (item["required_engine_version"].IsDefined())
	{
		rule_loader::context ctx(item, "required_engine_version", "", parent);
		rule_loader::engine_version_info v(ctx);

		decode_val(item, "required_engine_version", v.version, ctx);
		loader.define(cfg, v);
	}
	else if(item["required_plugin_versions"].IsDefined())
	{
		const YAML::Node& req_plugin_vers = item["required_plugin_versions"];
		rule_loader::context ctx(req_plugin_vers, "required_plugin_versions", "", parent);

		THROW(!req_plugin_vers.IsSequence(),
		       "Value of required_plugin_versions must be a sequence",
		       ctx);

		for(const YAML::Node& plugin : req_plugin_vers)
		{
			rule_loader::plugin_version_info::requirement r;

			// Use a temp context until we can get a name
			rule_loader::context tmp(plugin, "plugin version", "", ctx);
			THROW(!plugin.IsMap(), "Plugin version must be a mapping", tmp);
			decode_val(plugin, "name", r.name, tmp);
			rule_loader::context pctx(plugin, "plugin version", r.name, ctx);
			rule_loader::plugin_version_info v(pctx);
			decode_val(plugin, "version", r.version, pctx);
			v.alternatives.push_back(r);

			const YAML::Node& alternatives = plugin["alternatives"];
			if(alternatives.IsDefined())
			{
				THROW(!alternatives.IsSequence(),
					"Value of plugin version alternatives must be a sequence",
					pctx);
				for (const auto &req : alternatives)
				{
					tmp = rule_loader::context(req, "plugin version alternative", "", pctx);
					THROW(!req.IsMap(), "Plugin version alternative must be a mapping", tmp);
					decode_val(req, "name", r.name, tmp);
					tmp = rule_loader::context(req, "plugin version alternative", r.name, pctx);
					decode_val(req, "version", r.version, tmp);
					v.alternatives.push_back(r);
				}
			}

			loader.define(cfg, v);
		}
	}
	else if(item["list"].IsDefined())
	{
		std::string name;
		// Using tmp context until name is decoded
		rule_loader::context tmp(item, "list", "", parent);
		decode_val(item, "list", name, tmp);

		rule_loader::context ctx(item, "list", name, parent);
		rule_loader::list_info v(ctx);

		bool append = false;
		decode_val(item, "list", v.name, ctx);
		decode_items(item, v.items, ctx);

		decode_optional_val(item, "append", append, ctx);

		if(append)
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
		std::string name;
		// Using tmp context until name is decoded
		rule_loader::context tmp(item, "macro", "", parent);
		decode_val(item, "macro", name, tmp);

		rule_loader::context ctx(item, "macro", name, parent);
		rule_loader::macro_info v(ctx);
		v.name = name;

		bool append = false;
		decode_val(item, "condition", v.cond, ctx);

		// Now set the proper context for the condition now that we know it exists
		v.cond_ctx = rule_loader::context(item["condition"], "condition", "", ctx);

		decode_optional_val(item, "append", append, ctx);

		if(append)
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
		std::string name;

		// Using tmp context until name is decoded
		rule_loader::context tmp(item, "rule", "", parent);
		decode_val(item, "rule", name, tmp);

		rule_loader::context ctx(item, "rule", name, parent);
		rule_loader::rule_info v(ctx);
		v.name = name;

		bool append = false;
		v.enabled = true;
		v.warn_evttypes = true;
		v.skip_if_unknown_filter = false;

		decode_optional_val(item, "append", append, ctx);

		if(append)
		{
			decode_optional_val(item, "condition", v.cond, ctx);
			if(item["condition"].IsDefined())
			{
				v.cond_ctx = rule_loader::context(item["condition"], "condition", "", ctx);
			}
			read_rule_exceptions(item, v, ctx, append);
			loader.append(cfg, v);
		}
		else
		{
			// If the rule does *not* have any of
			// condition/output/desc/priority, it *must*
			// have an enabled property. Use the enabled
			// property to set the enabled status of an
			// earlier rule.
			if (!item["condition"].IsDefined() &&
			    !item["output"].IsDefined() &&
			    !item["desc"].IsDefined() &&
			    !item["priority"].IsDefined())
			{
				decode_val(item, "enabled", v.enabled, ctx);
				loader.enable(cfg, v);
			}
			else
			{
				string priority;

				// All of these are required
				decode_val(item, "condition", v.cond, ctx);
				v.cond_ctx = rule_loader::context(item["condition"], "condition", "", ctx);

				decode_val(item, "output", v.output, ctx);
				v.output_ctx = rule_loader::context(item["output"], "output", "", ctx);

				decode_val(item, "desc", v.desc, ctx);
				decode_val(item, "priority", priority, ctx);

				v.output = trim(v.output);
				v.source = falco_common::syscall_source;
				rule_loader::context prictx(item["priority"], "priority value", "", ctx);
				THROW(!falco_common::parse_priority(priority, v.priority),
				       "Invalid priority", prictx);
				decode_optional_val(item, "source", v.source, ctx);
				decode_optional_val(item, "enabled", v.enabled, ctx);
				decode_optional_val(item, "warn_evttypes", v.warn_evttypes, ctx);
				decode_optional_val(item, "skip-if-unknown-filter", v.skip_if_unknown_filter, ctx);
				decode_tags(item, v.tags, ctx);
				read_rule_exceptions(item, v, ctx, append);
				loader.define(cfg, v);
			}
		}
	}
	else
	{
		rule_loader::context ctx(item, "unknown", "", parent);
		cfg.res->add_warning(load_result::LOAD_UNKNOWN_ITEM, "Unknown top level item", ctx);
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
		rule_loader::context ctx(cfg.name);
		cfg.res->add_error(load_result::LOAD_ERR_YAML_PARSE, e.what(), ctx);
		return false;
	}

	for (auto doc = docs.begin(); doc != docs.end(); doc++)
	{
		if (doc->IsDefined() && !doc->IsNull())
		{
			rule_loader::context ctx(cfg.name);

			try {
				THROW(!doc->IsMap() && !doc->IsSequence(),
				       "Rules content is not yaml",
				       ctx);

				THROW(!doc->IsSequence(),
				       "Rules content is not yaml array of objects",
				       ctx);

				for (auto it = doc->begin(); it != doc->end(); it++)
				{
					if (!it->IsNull())
					{
						read_item(cfg, loader, *it, ctx);
					}
				}
			}
			catch (rule_loader::rule_load_exception &e)
			{
				cfg.res->add_error(e.ec, e.msg, e.ctx);

				// Although we *could* continue on to the next doc,
				// as it's effectively a new rules file, for
				// consistency we stop at the first error.
				return false;
			};
		}
	}

	return true;
}
