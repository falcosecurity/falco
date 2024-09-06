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
#include <vector>
#include <set>
#include <sstream>

#include "rule_loader_reader.h"
#include "falco_engine_version.h"
#include "rule_loading_messages.h"
#include "yaml_helper.h"
#include <libsinsp/logger.h>

#include <re2/re2.h>

#define THROW(cond, err, ctx)    { if ((cond)) { throw rule_loader::rule_load_exception(falco::load_result::LOAD_ERR_YAML_VALIDATE, (err), (ctx)); } }

// Sinsp Filter grammar tokens taken from "libsinsp/filter/parser.h"
// These regular expressions are used here to check for invalid macro/list names
// todo(mrgian): to avoid code duplication we can move regex definitions in libsinsp/filter/parser.h
// and include it here instead of redefining them.
#define RGX_IDENTIFIER "([a-zA-Z]+[a-zA-Z0-9_]*)"
#define RGX_BARESTR    "([^()\"'[:space:]=,]+)"

static re2::RE2 s_rgx_identifier(RGX_IDENTIFIER, re2::RE2::POSIX);
static re2::RE2 s_rgx_barestr(RGX_BARESTR, re2::RE2::POSIX);

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

	rule_loader::context valctx(val, rule_loader::context::VALUE_FOR, key, ctx);
	THROW(!val.IsScalar(), "Value is not a scalar value", valctx);
	THROW(val.Scalar().empty(), "Value must be non-empty", valctx);

	THROW(!YAML::convert<T>::decode(val, out), "Can't decode YAML scalar value", valctx);
}

template <typename T>
static void decode_val_generic(const YAML::Node& item, const char *key, std::optional<T>& out, const rule_loader::context& ctx, bool optional)
{
	T decoded;
	decode_val_generic(item, key, decoded, ctx, optional);
	out = decoded;
}

template <typename T>
void rule_loader::reader::decode_val(const YAML::Node& item, const char *key, T& out, const rule_loader::context& ctx)
{
	bool optional = false;

	decode_val_generic(item, key, out, ctx, optional);
}

template void rule_loader::reader::decode_val<std::string>(const YAML::Node& item, const char *key, std::string& out, const rule_loader::context& ctx);

template <typename T>
void rule_loader::reader::decode_optional_val(const YAML::Node& item, const char *key, T& out, const rule_loader::context& ctx)
{
	bool optional = true;

	decode_val_generic(item, key, out, ctx, optional);
}

template void rule_loader::reader::decode_optional_val<std::string>(const YAML::Node& item, const char *key, std::string& out, const rule_loader::context& ctx);

template void rule_loader::reader::decode_optional_val<bool>(const YAML::Node& item, const char *key, bool& out, const rule_loader::context& ctx);

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

	rule_loader::context valctx(val, rule_loader::context::VALUE_FOR, key, ctx);
	THROW(!val.IsSequence(), "Value is not a sequence", valctx);

	T value;
	for(const YAML::Node& v : val)
	{
		rule_loader::context ictx(v, rule_loader::context::LIST_ITEM, "", valctx);
		THROW(!v.IsScalar(), "sequence value is not scalar", ictx);
		THROW(!YAML::convert<T>::decode(v, value), "Can't decode YAML sequence value", ictx);
		inserter(value);
	}
}

template <typename T>
static void decode_items(const YAML::Node& item, std::vector<T>& out,
		       const rule_loader::context& ctx)
{
	bool optional = false;

	std::function<void(T)> inserter = [&out] (T value) {
		out.push_back(value);
	};

	decode_seq(item, "items", inserter, ctx, optional);
}

template <typename T>
static void decode_tags(const YAML::Node& item, std::set<T>& out,
		       const rule_loader::context& ctx)
{
	bool optional = true;

	std::function<void(T)> inserter = [&out] (T value) {
		out.insert(value);
	};

	decode_seq(item, "tags", inserter, ctx, optional);
}

template <typename T>
static void decode_tags(const YAML::Node& item, std::optional<std::set<T>>& out,
		       const rule_loader::context& ctx)
{
	std::set<T> decoded;
	decode_tags(item, decoded, ctx);
	out = decoded;
}

static void decode_overrides(const YAML::Node& item,
				std::set<std::string>& overridable_append,
				std::set<std::string>& overridable_replace,
				std::set<std::string>& out_append,
				std::set<std::string>& out_replace,
				const rule_loader::context& ctx)
{
	const YAML::Node& val = item["override"];

	if(!val.IsDefined())
	{
		return;
	}

	rule_loader::context overridectx(item, rule_loader::context::OVERRIDE, "", ctx);

	for(YAML::const_iterator it=val.begin();it!=val.end();++it)
	{
		std::string key = it->first.as<std::string>();
		std::string operation = it->second.as<std::string>();

		bool is_overridable_append = overridable_append.find(it->first.as<std::string>()) != overridable_append.end();
		bool is_overridable_replace = overridable_replace.find(it->first.as<std::string>()) != overridable_replace.end();

		if (operation == "append")
		{
			rule_loader::context keyctx(it->first, rule_loader::context::OVERRIDE, key, overridectx);
			THROW(!is_overridable_append, std::string("Key '") + key + std::string("' cannot be appended to, use 'replace' instead"), keyctx);

			out_append.insert(key);
		}
		else if (operation == "replace")
		{
			rule_loader::context keyctx(it->first, rule_loader::context::OVERRIDE, key, overridectx);
			THROW(!is_overridable_replace, std::string("Key '") + key + std::string("' cannot be replaced"), keyctx);

			out_replace.insert(key);
		}
		else
		{
			rule_loader::context operationctx(it->second, rule_loader::context::VALUE_FOR, key, overridectx);
			std::stringstream err_ss;
			err_ss << "Invalid override operation for key '" << key << "': '" << operation << "'. "
				   << "Allowed values are: ";
			if (is_overridable_append)
			{
				err_ss << "append ";
			}
			if (is_overridable_replace)
			{
				err_ss << "replace ";
			}

			THROW(true, err_ss.str(), operationctx);
		}
	}
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

	rule_loader::context valctx(val, rule_loader::context::VALUE_FOR, (key == NULL ? "" : key), ctx);

	if (val.IsScalar())
	{
		THROW(val.Scalar().empty(), "Value must be non-empty", valctx);
		out.is_list = false;
		THROW(!YAML::convert<std::string>::decode(val, out.item), "Could not decode scalar value", valctx);
	}
	if (val.IsSequence())
	{
		out.is_list = true;
		for(const YAML::Node& v : val)
		{
			rule_loader::rule_exception_info::entry tmp;
			rule_loader::context lctx(v, rule_loader::context::EXCEPTION, "", valctx);

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
	rule_loader::configuration& cfg,
	const YAML::Node& item,
	std::vector<rule_loader::rule_exception_info>& exceptions,
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

	rule_loader::context exes_ctx(exs, rule_loader::context::EXCEPTIONS, "", parent);

	THROW(!exs.IsSequence(), "Rule exceptions must be a sequence", exes_ctx);

	for (auto &ex : exs)
	{
		// Make a temp context to verify simple properties
		// about the exception.
		std::string name;
		rule_loader::context tmp(ex, rule_loader::context::EXCEPTION, "", exes_ctx);

		THROW(!ex.IsMap(), "Rule exception must be a mapping", tmp);
		rule_loader::reader::decode_val(ex, "name", name, tmp);

		// Now use a real context including the exception name.
		rule_loader::context ex_ctx(ex, rule_loader::context::EXCEPTION, name, parent);
		rule_loader::rule_exception_info v_ex(ex_ctx);
		v_ex.name = name;

		// Check if an exception with the same name has already been defined
		for (auto &exception : exceptions)
		{
			if(v_ex.name == exception.name)
			{
				cfg.res->add_warning(falco::load_result::LOAD_EXCEPTION_NAME_NOT_UNIQUE, "Multiple definitions of exception '" + v_ex.name + "' in the same rule", ex_ctx);
			}
		}

		// note: the legacy lua loader used to throw a "xxx must strings" error

		// fields are optional when append is true
		decode_exception_fields(ex, v_ex.fields, ex_ctx, append);
		decode_exception_comps(ex, v_ex.comps, ex_ctx);
		const YAML::Node& exvals = ex["values"];
		if (exvals.IsDefined())
		{
			rule_loader::context vals_ctx(exvals, rule_loader::context::EXCEPTION_VALUES, "", ex_ctx);
			THROW(!exvals.IsSequence(),
			       "Rule exception values must be a sequence", vals_ctx);
			for (const auto &val : exvals)
			{
				rule_loader::context vctx(val, rule_loader::context::EXCEPTION_VALUE, "", vals_ctx);
				rule_loader::rule_exception_info::entry v_ex_val;

				decode_exception_values(val, v_ex_val, vctx);
				v_ex.values.push_back(v_ex_val);
			}
		} 
		else if (append)
		{
			cfg.res->add_warning(falco::load_result::LOAD_APPEND_NO_VALUES, "Overriding/appending exception with no values", ex_ctx);
		}
		exceptions.push_back(v_ex);
	}
}

static void read_rule_exceptions(
	rule_loader::configuration& cfg,
	const YAML::Node& item,
	std::optional<std::vector<rule_loader::rule_exception_info>>& exceptions,
	const rule_loader::context& parent,
	bool append)
{
	std::vector<rule_loader::rule_exception_info> decoded;
	read_rule_exceptions(cfg, item, decoded, parent, append);
	exceptions = decoded;
}

inline static bool check_update_expected(std::set<std::string>& expected_keys, const std::set<std::string>& overrides, const std::string& override_type, const std::string& key, const rule_loader::context& ctx)
{
	if (overrides.find(key) == overrides.end())
	{
		return false;
	}
	
	THROW(expected_keys.find(key) == expected_keys.end(),
		std::string("An ") + override_type + " override for '" + key + "' was specified but '" + key + "' is not defined", ctx);

	expected_keys.erase(key);

	return true;
}

void rule_loader::reader::read_item(
	rule_loader::configuration& cfg,
	rule_loader::collector& collector,
	const YAML::Node& item,
	const rule_loader::context& parent)
{
	{
		rule_loader::context tmp(item, rule_loader::context::RULES_CONTENT_ITEM, "", parent);
		THROW(!item.IsMap(), "Unexpected element type. "
		      "Each element should be a yaml associative array.", tmp);
	}

	if (item["required_engine_version"].IsDefined())
	{
		rule_loader::context ctx(item, rule_loader::context::REQUIRED_ENGINE_VERSION, "", parent);
		rule_loader::engine_version_info v(ctx);
		
		try
		{
			// Convert convert to an uint (more restrictive than converting to a string)
			uint32_t ver;
			decode_val(item, "required_engine_version", ver, ctx);

			// Build proper semver representation
			v.version = rule_loader::reader::get_implicit_engine_version(ver);
		} 
		catch(std::exception& e)
		{
			// Convert to string
			std::string ver;
			decode_val(item, "required_engine_version", ver, ctx);

			v.version = sinsp_version(ver);

			THROW(!v.version.is_valid(), "Unable to parse engine version '" + ver + "' as a semver string. Expected \"x.y.z\" semver format.", ctx);
		}

		collector.define(cfg, v);
	}
	else if(item["required_plugin_versions"].IsDefined())
	{
		const YAML::Node& req_plugin_vers = item["required_plugin_versions"];
		rule_loader::context ctx(req_plugin_vers, rule_loader::context::REQUIRED_PLUGIN_VERSIONS, "", parent);

		THROW(!req_plugin_vers.IsSequence(),
		       "Value of required_plugin_versions must be a sequence",
		       ctx);

		for(const YAML::Node& plugin : req_plugin_vers)
		{
			rule_loader::plugin_version_info::requirement r;

			// Use a temp context until we can get a name
			rule_loader::context tmp(plugin, rule_loader::context::REQUIRED_PLUGIN_VERSIONS_ENTRY, "", ctx);
			THROW(!plugin.IsMap(), "Plugin version must be a mapping", tmp);
			decode_val(plugin, "name", r.name, tmp);
			rule_loader::context pctx(plugin, rule_loader::context::REQUIRED_PLUGIN_VERSIONS_ENTRY, r.name, ctx);
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
					tmp = rule_loader::context(req, rule_loader::context::REQUIRED_PLUGIN_VERSIONS_ALTERNATIVE, "", pctx);
					THROW(!req.IsMap(), "Plugin version alternative must be a mapping", tmp);
					decode_val(req, "name", r.name, tmp);
					tmp = rule_loader::context(req, rule_loader::context::REQUIRED_PLUGIN_VERSIONS_ALTERNATIVE, r.name, pctx);
					decode_val(req, "version", r.version, tmp);
					v.alternatives.push_back(r);
				}
			}

			collector.define(cfg, v);
		}
	}
	else if(item["list"].IsDefined())
	{
		std::string name;
		// Using tmp context until name is decoded
		rule_loader::context tmp(item, rule_loader::context::LIST, "", parent);
		decode_val(item, "list", name, tmp);

		rule_loader::context ctx(item, rule_loader::context::LIST, name, parent);

		bool invalid_name = !re2::RE2::FullMatch(name, s_rgx_barestr);
		if(invalid_name)
		{
			cfg.res->add_warning(falco::load_result::LOAD_INVALID_LIST_NAME, "List has an invalid name. List names should match a regular expression: " RGX_BARESTR, ctx);
		}

		rule_loader::list_info v(ctx);

		bool append = false;
		decode_val(item, "list", v.name, ctx);
		decode_items(item, v.items, ctx);

		decode_optional_val(item, "append", append, ctx);
		if(append)
		{
			cfg.res->add_warning(falco::load_result::LOAD_DEPRECATED_ITEM, WARNING_APPEND, ctx);
		}

		std::set<std::string> override_append, override_replace;
		std::set<std::string> overridable {"items"};
		decode_overrides(item, overridable, overridable, override_append, override_replace, ctx);
		bool has_overrides = !override_append.empty() || !override_replace.empty();

		THROW(append && has_overrides, ERROR_OVERRIDE_APPEND, ctx);

		// Since a list only has items, if we have chosen to append them we can append the entire object
		// otherwise we just want to redefine the list.
		append |= override_append.find("items") != override_append.end();

		if(append)
		{
			collector.append(cfg, v);
		}
		else
		{
			collector.define(cfg, v);
		}
	}
	else if(item["macro"].IsDefined())
	{
		std::string name;
		// Using tmp context until name is decoded
		rule_loader::context tmp(item, rule_loader::context::MACRO, "", parent);
		decode_val(item, "macro", name, tmp);

		rule_loader::context ctx(item, rule_loader::context::MACRO, name, parent);

		bool invalid_name = !re2::RE2::FullMatch(name, s_rgx_identifier);
		if(invalid_name)
		{
			cfg.res->add_warning(falco::load_result::LOAD_INVALID_MACRO_NAME, "Macro has an invalid name. Macro names should match a regular expression: " RGX_IDENTIFIER, ctx);
		}

		rule_loader::macro_info v(ctx);
		v.name = name;

		bool append = false;
		decode_val(item, "condition", v.cond, ctx);

		// Now set the proper context for the condition now that we know it exists
		v.cond_ctx = rule_loader::context(item["condition"], rule_loader::context::MACRO_CONDITION, "", ctx);

		decode_optional_val(item, "append", append, ctx);
		if(append)
		{
			cfg.res->add_warning(falco::load_result::LOAD_DEPRECATED_ITEM, WARNING_APPEND, ctx);
		}

		std::set<std::string> override_append, override_replace;
		std::set<std::string> overridable {"condition"};
		decode_overrides(item, overridable, overridable, override_append, override_replace, ctx);
		bool has_overrides = !override_append.empty() || !override_replace.empty();

		THROW((append && has_overrides), ERROR_OVERRIDE_APPEND, ctx);

		// Since a macro only has a condition, if we have chosen to append to it we can append the entire object
		// otherwise we just want to redefine the macro.
		append |= override_append.find("condition") != override_append.end();

		if(append)
		{
			collector.append(cfg, v);
		}
		else
		{
			collector.define(cfg, v);
		}
	}
	else if(item["rule"].IsDefined())
	{
		std::string name;

		// Using tmp context until name is decoded
		rule_loader::context tmp(item, rule_loader::context::RULE, "", parent);
		decode_val(item, "rule", name, tmp);

		rule_loader::context ctx(item, rule_loader::context::RULE, name, parent);

		bool has_append_flag = false;
		decode_optional_val(item, "append", has_append_flag, ctx);
		if(has_append_flag)
		{
			cfg.res->add_warning(falco::load_result::LOAD_DEPRECATED_ITEM, WARNING_APPEND, ctx);
		}

		std::set<std::string> override_append, override_replace;
		std::set<std::string> overridable_append {"condition", "output", "desc", "tags", "exceptions"};
		std::set<std::string> overridable_replace {
			"condition", "output", "desc", "priority", "tags", "exceptions", "enabled", "warn_evttypes", "skip-if-unknown-filter"};
		decode_overrides(item, overridable_append, overridable_replace, override_append, override_replace, ctx);
		bool has_overrides_append = !override_append.empty();
		bool has_overrides_replace = !override_replace.empty();
		bool has_overrides = has_overrides_append || has_overrides_replace;

		THROW((has_append_flag && has_overrides), ERROR_OVERRIDE_APPEND, ctx);

		if(has_overrides)
		{
			std::set<std::string> expected_keys;
			for (auto& key : overridable_append)
			{
				if (item[key].IsDefined())
				{
					expected_keys.insert(key);
				}
			}

			for (auto& key : overridable_replace)
			{
				if (item[key].IsDefined())
				{
					expected_keys.insert(key);
				}
			}

			// expected_keys is (appendable U replaceable) ^ (defined)
			
			if (has_overrides_append)
			{
				rule_loader::rule_update_info v(ctx);
				v.name = name;
				if (check_update_expected(expected_keys, override_append, "append", "condition", ctx))
				{
					decode_val(item, "condition", v.cond, ctx);
				}

				if (check_update_expected(expected_keys, override_append, "append", "exceptions", ctx))
				{
					read_rule_exceptions(cfg, item, v.exceptions, ctx, true);
				}

				if (check_update_expected(expected_keys, override_append, "append", "output", ctx))
				{
					decode_val(item, "output", v.output, ctx);
				}

				if (check_update_expected(expected_keys, override_append, "append", "desc", ctx))
				{
					decode_val(item, "desc", v.desc, ctx);
				}

				if (check_update_expected(expected_keys, override_append, "append", "tags", ctx))
				{
					decode_tags(item, v.tags, ctx);
				}
				
				collector.append(cfg, v);
			}

			if (has_overrides_replace)
			{
				rule_loader::rule_update_info v(ctx);
				v.name = name;
				if (check_update_expected(expected_keys, override_replace, "replace", "condition", ctx))
				{
					decode_val(item, "condition", v.cond, ctx);
				}

				if (check_update_expected(expected_keys, override_replace, "replace", "exceptions", ctx))
				{
					read_rule_exceptions(cfg, item, v.exceptions, ctx, false);
				}

				if (check_update_expected(expected_keys, override_replace, "replace", "output", ctx))
				{
					decode_val(item, "output", v.output, ctx);
				}

				if (check_update_expected(expected_keys, override_replace, "replace", "desc", ctx))
				{
					decode_val(item, "desc", v.desc, ctx);
				}

				if (check_update_expected(expected_keys, override_replace, "replace", "tags", ctx))
				{
					decode_tags(item, v.tags, ctx);
				}

				if (check_update_expected(expected_keys, override_replace, "replace", "priority", ctx))
				{
					std::string priority;
					decode_val(item, "priority", priority, ctx);
					rule_loader::context prictx(item["priority"], rule_loader::context::RULE_PRIORITY, "", ctx);
					falco_common::priority_type parsed_priority;
					THROW(!falco_common::parse_priority(priority, parsed_priority), "Invalid priority", prictx);
					v.priority = parsed_priority;
				}

				if (check_update_expected(expected_keys, override_replace, "replace", "enabled", ctx))
				{
					decode_val(item, "enabled", v.enabled, ctx);
				}

				if (check_update_expected(expected_keys, override_replace, "replace", "warn_evttypes", ctx))
				{
					decode_val(item, "warn_evttypes", v.warn_evttypes, ctx);
				}

				if (check_update_expected(expected_keys, override_replace, "replace", "skip-if-unknown-filter", ctx))
				{
					decode_val(item, "skip-if-unknown-filter", v.skip_if_unknown_filter, ctx);
				}

				collector.selective_replace(cfg, v);
			}

			// if any expected key has not been defined throw an error
			for (const auto &key : expected_keys) {
				rule_loader::context keyctx(item[key], rule_loader::context::OVERRIDE, key, ctx);
				THROW(true, "Unexpected key '" + key + "': no corresponding entry under 'override' is defined.", keyctx);
			}
		}
		else if(has_append_flag)
		{
			rule_loader::rule_update_info v(ctx);
			v.name = name;

			if(item["condition"].IsDefined())
			{
				v.cond_ctx = rule_loader::context(item["condition"], rule_loader::context::RULE_CONDITION, "", ctx);
				decode_val(item, "condition", v.cond, ctx);
			}

			if(item["exceptions"].IsDefined())
			{
				read_rule_exceptions(cfg, item, v.exceptions, ctx, true);
			}

			// TODO restore this error and update testing
			//THROW((!v.cond.has_value() && !v.exceptions.has_value()),
			//       "Appended rule must have exceptions or condition property",
			//       v.ctx);

			collector.append(cfg, v);
		}
		else
		{
			rule_loader::rule_info v(ctx);
			v.name = name;
			v.enabled = true;
			v.warn_evttypes = true;
			v.skip_if_unknown_filter = false;

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
				cfg.res->add_warning(falco::load_result::LOAD_DEPRECATED_ITEM, WARNING_ENABLED, ctx);
				collector.enable(cfg, v);
			}
			else
			{
				std::string priority;

				// All of these are required
				decode_val(item, "condition", v.cond, ctx);
				v.cond_ctx = rule_loader::context(item["condition"], rule_loader::context::RULE_CONDITION, "", ctx);

				decode_val(item, "output", v.output, ctx);
				v.output_ctx = rule_loader::context(item["output"], rule_loader::context::RULE_OUTPUT, "", ctx);

				decode_val(item, "desc", v.desc, ctx);
				decode_val(item, "priority", priority, ctx);

				v.output = trim(v.output);
				v.source = falco_common::syscall_source;
				rule_loader::context prictx(item["priority"], rule_loader::context::RULE_PRIORITY, "", ctx);
				THROW(!falco_common::parse_priority(priority, v.priority),
				       "Invalid priority", prictx);
				decode_optional_val(item, "source", v.source, ctx);
				decode_optional_val(item, "enabled", v.enabled, ctx);
				decode_optional_val(item, "warn_evttypes", v.warn_evttypes, ctx);
				decode_optional_val(item, "skip-if-unknown-filter", v.skip_if_unknown_filter, ctx);
				decode_tags(item, v.tags, ctx);
				read_rule_exceptions(cfg, item, v.exceptions, ctx, false);
				collector.define(cfg, v);
			}
		}
	}
	else
	{
		rule_loader::context ctx(item, rule_loader::context::RULES_CONTENT_ITEM, "", parent);
		cfg.res->add_warning(falco::load_result::LOAD_UNKNOWN_ITEM, "Unknown top level item", ctx);
	}
}

bool rule_loader::reader::read(rule_loader::configuration& cfg, collector& collector, const nlohmann::json& schema)
{
	std::vector<YAML::Node> docs;
	yaml_helper reader;
	std::string schema_validation;
	rule_loader::context ctx(cfg.name);
	try
	{
		docs = reader.loadall_from_string(cfg.content, schema, &schema_validation);
	}
	catch (YAML::ParserException& e)
	{
		rule_loader::context ictx(e.mark, ctx);
		cfg.res->add_error(falco::load_result::LOAD_ERR_YAML_PARSE, e.what(), ictx);
		return false;
	}
	catch (std::exception& e)
	{
		cfg.res->add_error(falco::load_result::LOAD_ERR_YAML_PARSE, e.what(), ctx);
		return false;
	}
	catch (...)
	{
		cfg.res->add_error(falco::load_result::LOAD_ERR_YAML_PARSE, "unknown YAML parsing error", ctx);
		return false;
	}
	cfg.res->set_schema_validation_status(schema_validation);
	for (auto doc = docs.begin(); doc != docs.end(); doc++)
	{
		if (doc->IsDefined() && !doc->IsNull())
		{
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
						read_item(cfg, collector, *it, ctx);
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
			}
			catch (YAML::ParserException& e)
			{
				rule_loader::context ictx(e.mark, ctx);
				cfg.res->add_error(falco::load_result::LOAD_ERR_YAML_VALIDATE, e.what(), ictx);
				return false;
			}
			catch (std::exception& e)
			{
				cfg.res->add_error(falco::load_result::LOAD_ERR_VALIDATE, e.what(), ctx);
				return false;
			}
			catch (...)
			{
				cfg.res->add_error(falco::load_result::LOAD_ERR_VALIDATE, "unknown validation error", ctx);
				return false;
			}
		}
	}

	return true;
}
