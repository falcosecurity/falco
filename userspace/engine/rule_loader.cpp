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

#include "falco_engine.h"
#include "falco_utils.h"
#include "rule_loader.h"
#include "filter_macro_resolver.h"
#include "filter_evttype_resolver.h"
#include "filter_warning_resolver.h"

#define MAX_VISIBILITY		((uint32_t) -1)
#define THROW(cond, err)    { if (cond) { throw falco_exception(err); } }

static string s_container_info_fmt = "%container.info";
static string s_default_extra_fmt  = "%container.name (id=%container.id)";

using namespace std;
using namespace libsinsp::filter;

// todo(jasondellaluce): this breaks string escaping in lists and exceptions
static void quote_item(string& e)
{
	if (e.find(" ") != string::npos && e[0] != '"' && e[0] != '\'')
	{
		e = '"' + e + '"';
	}
}

static void paren_item(string& e)
{
	if(e[0] != '(')
	{
		e = '(' + e + ')';
	}
}

static inline bool is_operator_defined(const string& op)
{
	auto ops = libsinsp::filter::parser::supported_operators();
	return find(ops.begin(), ops.end(), op) != ops.end();
}

static inline bool is_operator_for_list(const string& op)
{
	auto ops = libsinsp::filter::parser::supported_operators(true);
	return find(ops.begin(), ops.end(), op) != ops.end();
}

static bool is_format_valid(const falco_source& source, string fmt, string& err)
{
	try
	{
		shared_ptr<gen_event_formatter> formatter;
		formatter = source.formatter_factory->create_formatter(fmt);
		return true;
	}
	catch(exception &e)
	{
		err = e.what();
		return false;
	}
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
	prev->ctx.append(info.ctx);
}

static void validate_exception_info(
	const falco_source& source,
	rule_loader::rule_exception_info &ex)
{
	if (ex.fields.is_list)
	{
		if (!ex.comps.is_valid())
		{
			ex.comps.is_list = true;
			for (size_t i = 0; i < ex.fields.items.size(); i++)
			{
				ex.comps.items.push_back({false, "="});
			}
		}
		THROW(ex.fields.items.size() != ex.comps.items.size(),
			"Rule exception item " + ex.name
				+ ": fields and comps lists must have equal length");
		for (auto &v : ex.comps.items)
		{
			THROW(!is_operator_defined(v.item),
				"Rule exception item " + ex.name + ": comparison operator "
					+ v.item + " is not a supported comparison operator");
		}
		for (auto &v : ex.fields.items)
		{
			THROW(!source.is_field_defined(v.item),
				"Rule exception item " + ex.name + ": field name "
					+ v.item + " is not a supported filter field");
		}
	}
	else
	{
		if (!ex.comps.is_valid())
		{
			ex.comps.is_list = false;
			ex.comps.item = "in";
		}
		THROW(ex.comps.is_list, "Rule exception item "
			+ ex.name + ": fields and comps must both be strings");
		THROW(!is_operator_defined(ex.comps.item),
			"Rule exception item " + ex.name + ": comparison operator "
				+ ex.comps.item + " is not a supported comparison operator");
		THROW(!source.is_field_defined(ex.fields.item),
			"Rule exception item " + ex.name + ": field name "
				+ ex.fields.item + " is not a supported filter field");
	}
}

static void build_rule_exception_infos(
	vector<rule_loader::rule_exception_info>& exceptions,
	set<string>& exception_fields,
	string& condition)
{
	string tmp;
	for (auto &ex : exceptions)
	{
		string icond;
		if(!ex.fields.is_list)
		{
			for (auto &val : ex.values)
			{
				THROW(val.is_list, "Expected values array for item "
					+ ex.name + " to contain a list of strings");
				icond += icond.empty()
					? ("(" + ex.fields.item + " "
						+ ex.comps.item + " (")
					: ", ";
				exception_fields.insert(ex.fields.item);
				tmp = val.item;
				quote_item(tmp);
				icond += tmp;
			}
			icond += icond.empty() ? "" : "))";
		}
		else
		{
			icond = "(";
			for (auto &values : ex.values)
			{
				THROW(ex.fields.items.size() != values.items.size(),
					"Exception item " + ex.name
						+ ": fields and values lists must have equal length");
				icond += icond == "(" ? "" : " or ";
				icond += "(";
				uint32_t k = 0;
				string istr;
				for (auto &field : ex.fields.items)
				{
					icond += k == 0 ? "" : " and ";
					if (values.items[k].is_list)
					{
						istr = "(";
						for (auto &v : values.items[k].items)
						{
							tmp = v.item;
							quote_item(tmp);
							istr += istr == "(" ? "" : ", ";
							istr += tmp;
						}
						istr += ")";
					}
					else
					{
						istr = values.items[k].item;
						if(is_operator_for_list(ex.comps.items[k].item))
						{
							paren_item(istr);
						}
						else
						{
							quote_item(istr);
						}
					}
					icond += " " + field.item;
					icond += " " + ex.comps.items[k].item + " " + istr;
					exception_fields.insert(field.item);
					k++;
				}
				icond += ")";
			}
			icond += ")";
			if (icond == "()")
			{
				icond = "";
			}
		}
		condition += icond.empty() ? "" : " and not " + icond;
	}
}

// todo(jasondellaluce): this breaks string escaping in lists
static bool resolve_list(string& cnd, const rule_loader::list_info& list)
{
	static string blanks = " \t\n\r";
	static string delims = blanks + "(),=";
	string new_cnd;
	size_t start, end;
	bool used = false;
	start = cnd.find(list.name);
	while (start != string::npos)
	{
		// the characters surrounding the name must
		// be delims of beginning/end of string
		end = start + list.name.length();
		if ((start == 0 || delims.find(cnd[start - 1]) != string::npos)
			&& (end >= cnd.length() || delims.find(cnd[end]) != string::npos))
		{
			// shift pointers to consume all whitespaces
			while (start > 0
				&& blanks.find(cnd[start - 1]) != string::npos)
			{
				start--;
			}
			while (end < cnd.length()
				&& blanks.find(cnd[end]) != string::npos)
			{
				end++;
			}
			// create substitution string by concatenating all values
			string sub = "";
			for (auto &v : list.items)
			{
				if (!sub.empty())
				{
					sub += ", ";
				}
				sub += v;
			}
			// if substituted list is empty, we need to
			// remove a comma from the left or the right
			if (sub.empty())
			{
				if (start > 0 && cnd[start - 1] == ',')
				{
					start--;
				}
				else if (end < cnd.length() && cnd[end] == ',')
				{
					end++;
				}
			}
			// compose new string with substitution
			new_cnd = "";
			if (start > 0)
			{
				new_cnd += cnd.substr(0, start) + " ";
			}
			new_cnd += sub + " ";
			if (end <= cnd.length())
			{
				new_cnd += cnd.substr(end);
			}
			cnd = new_cnd;
			start += sub.length() + 1;
			used = true;
		}
		start = cnd.find(list.name, start + 1);
	}
	return used;
}

static void resolve_macros(
	indexed_vector<rule_loader::macro_info>& macros,
	shared_ptr<ast::expr>& ast,
	uint32_t visibility,
	const string& on_unknown_err_prefix)
{
	filter_macro_resolver macro_resolver;
	for (auto &m : macros)
	{
		if (m.index < visibility)
		{
			macro_resolver.set_macro(m.name, m.cond_ast);
		}
	}
	macro_resolver.run(ast);
	THROW(!macro_resolver.get_unknown_macros().empty(),
		on_unknown_err_prefix + "Undefined macro '"
			+ *macro_resolver.get_unknown_macros().begin()
			+ "' used in filter.");
	for (auto &m : macro_resolver.get_resolved_macros())
	{
		macros.at(m)->used = true;
	}
}

// note: there is no visibility order between filter conditions and lists
static shared_ptr<ast::expr> parse_condition(
	string condition,
	indexed_vector<rule_loader::list_info>& lists)
{
	for (auto &l : lists)
	{
		if (resolve_list(condition, l))
		{
			l.used = true;
		}
	}
	libsinsp::filter::parser p(condition);
	p.set_max_depth(1000);
	try
	{
		shared_ptr<ast::expr> res_ptr(p.parse());
		return res_ptr;
	}
	catch (const sinsp_exception& e)
	{
		throw falco_exception("Compilation error when compiling \""
			+ condition + "\": " + to_string(p.get_pos().col) + ": " + e.what());
	}
}

static void apply_output_substitutions(
	rule_loader::configuration& cfg,
	string& out)
{
	if (out.find(s_container_info_fmt) != string::npos)
	{
		if (cfg.replace_output_container_info)
		{
			out = replace(out, s_container_info_fmt, cfg.output_extra);
			return;
		}
		out = replace(out, s_container_info_fmt, s_default_extra_fmt);
	}
	out += cfg.output_extra.empty() ? "" : " " + cfg.output_extra;
}

void rule_loader::clear()
{
	m_cur_index = 0;
	m_rule_infos.clear();
	m_list_infos.clear();
	m_macro_infos.clear();
	m_required_plugin_versions.clear();
}

bool rule_loader::is_plugin_compatible(
		const string &name,
		const string &version,
		string &required_version)
{
	set<string> required_plugin_versions;
	sinsp_plugin::version plugin_version(version);
	if(!plugin_version.m_valid)
	{
		throw falco_exception(
			string("Plugin version string ") + version + " not valid");
	}
	auto it = m_required_plugin_versions.find(name);
	if (it != m_required_plugin_versions.end())
	{
		for (auto &rversion : it->second)
		{
			sinsp_plugin::version req_version(rversion);
			if (!plugin_version.check(req_version))
			{
				required_version = rversion;
				return false;
			}
		}
	}
	return true;
}

void rule_loader::define(configuration& cfg, engine_version_info& info)
{
	auto v = falco_engine::engine_version();
	THROW(v < info.version, "Rules require engine version "
		+ to_string(info.version) + ", but engine version is " + to_string(v));
}

void rule_loader::define(configuration& cfg, plugin_version_info& info)
{
	m_required_plugin_versions[info.name].insert(info.version);
}

void rule_loader::define(configuration& cfg, list_info& info)
{
	define_info(m_list_infos, info, m_cur_index++);
}

void rule_loader::append(configuration& cfg, list_info& info)
{
	auto prev = m_list_infos.at(info.name);
	THROW(!prev, "List " + info.name +
		" has 'append' key but no list by that name already exists");
	prev->items.insert(prev->items.end(), info.items.begin(), info.items.end());
	append_info(prev, info, m_cur_index++);
}

void rule_loader::define(configuration& cfg, macro_info& info)
{
	if (!cfg.sources.at(info.source))
	{
		cfg.warnings.push_back("Macro " + info.name
			+ ": warning (unknown-source): unknown source "
			+ info.source + ", skipping");
		return;
	}
	define_info(m_macro_infos, info, m_cur_index++);
}

void rule_loader::append(configuration& cfg, macro_info& info)
{
	auto prev = m_macro_infos.at(info.name);
	THROW(!prev, "Macro " + info.name
		+ " has 'append' key but no macro by that name already exists");
	prev->cond += " ";
	prev->cond += info.cond;
	append_info(prev, info, m_cur_index++);
}

void rule_loader::define(configuration& cfg, rule_info& info)
{
	auto source = cfg.sources.at(info.source);
	if (!source)
	{
		cfg.warnings.push_back("Rule " + info.name
			+ ": warning (unknown-source): unknown source "
			+ info.source + ", skipping");
		return;
	}

	auto prev = m_macro_infos.at(info.name);
	THROW(prev && prev->source != info.source,
		"Rule " + info.name + " has been re-defined with a different source");

	for (auto &ex : info.exceptions)
	{
		THROW(!ex.fields.is_valid(), "Rule exception item "
			+ ex.name + ": must have fields property with a list of fields");
		validate_exception_info(*source, ex);
	}

	define_info(m_rule_infos, info, m_cur_index++);
}

void rule_loader::append(configuration& cfg, rule_info& info)
{
	auto prev = m_rule_infos.at(info.name);
	THROW(!prev, "Rule " + info.name
		+ " has 'append' key but no rule by that name already exists");
	THROW(info.cond.empty() && info.exceptions.empty(),
		"Appended rule must have exceptions or condition property");

	auto source = cfg.sources.at(prev->source);
	// note: this is not supposed to happen
	THROW(!source, "Rule " + prev->name
		+ ": error (unknown-source): unknown source " + prev->source);

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
			THROW(!ex.fields.is_valid(), "Rule exception new item "
				+ ex.name + ": must have fields property with a list of fields");
			THROW(ex.values.empty(), "Rule exception new item "
				+ ex.name + ": must have fields property with a list of values");
			validate_exception_info(*source, ex);
			prev->exceptions.push_back(ex);
		}
		else
		{
			THROW(ex.fields.is_valid(),
				"Can not append exception fields to existing rule, only values");
			THROW(ex.comps.is_valid(),
				"Can not append exception comps to existing rule, only values");
			prev_ex->values.insert(
				prev_ex->values.end(), ex.values.begin(), ex.values.end());
		}
	}
	append_info(prev, info, m_cur_index++);
}

void rule_loader::enable(configuration& cfg, rule_info& info)
{
	auto prev = m_rule_infos.at(info.name);
	THROW(!prev, "Rule " + info.name
		+ " has 'enabled' key but no rule by that name already exists");
	prev->enabled = info.enabled;
}

void rule_loader::compile_list_infos(configuration& cfg, indexed_vector<list_info>& out)
{
	string tmp;
	vector<string> used;
	for (auto &list : m_list_infos)
	{
		try
		{
			list_info v = list;
			v.items.clear();
			for (auto &item : list.items)
			{
				auto ref = m_list_infos.at(item);
				if (ref && ref->index < list.visibility)
				{
					used.push_back(ref->name);
					for (auto val : ref->items)
					{
						quote_item(val);
						v.items.push_back(val);
					}
				}
				else
				{
					tmp = item;
					quote_item(tmp);
					v.items.push_back(tmp);
				}
			}
			v.used = false;
			out.insert(v, v.name);
		}
		catch (exception& e)
		{
			throw falco_exception(list.ctx.error(e.what()));
		}
	}
	for (auto &v : used)
	{
		out.at(v)->used = true;
	}
}

// note: there is a visibility ordering between macros
void rule_loader::compile_macros_infos(
	configuration& cfg,
	indexed_vector<list_info>& lists,
	indexed_vector<macro_info>& out)
{
	set<string> used;
	context* info_ctx = NULL;
	try
	{
		for (auto &m : m_macro_infos)
		{
			info_ctx = &m.ctx;
			macro_info entry = m;
			entry.cond_ast = parse_condition(m.cond, lists);
			entry.used = false;
			out.insert(entry, m.name);
		}
		for (auto &m : out)
		{
			info_ctx = &m.ctx;
			resolve_macros(out, m.cond_ast, m.visibility,
				"Compilation error when compiling \"" + m.cond + "\": ");
		}
	}
	catch (exception& e)
	{
		throw falco_exception(info_ctx->error(e.what()));
	}
}


void rule_loader::compile_rule_infos(
	configuration& cfg,
	indexed_vector<list_info>& lists,
	indexed_vector<macro_info>& macros,
	indexed_vector<falco_rule>& out)
{
	string err, condition;
	set<string> warn_codes;
	filter_warning_resolver warn_resolver;
	for (auto &r : m_rule_infos)
	{
		try
		{
			// skip the rule if below the minimum priority
			if (r.priority > cfg.min_priority)
			{
				continue;
			}

			auto source = cfg.sources.at(r.source);
			// note: this is not supposed to happen
			THROW(!source, "Rule " + r.name
				+ ": error (unknown-source): unknown source " + r.source);

			// build filter AST by parsing the condition, building exceptions,
			// and resolving lists and macros
			falco_rule rule;

			condition = r.cond;
			if (!r.exceptions.empty())
			{
				build_rule_exception_infos(
					r.exceptions, rule.exception_fields, condition);
			}
			auto ast = parse_condition(condition, lists);
			resolve_macros(macros, ast, MAX_VISIBILITY, "");

			// check for warnings in the filtering condition
			warn_codes.clear();
			if (warn_resolver.run(ast.get(), warn_codes))
			{
				for (auto &w : warn_codes)
				{
					cfg.warnings.push_back(
						"Rule " + r.name + ": warning (" + w + "):\n    "
						+ falco::utils::wrap_text(warn_resolver.format(w), 4, 50));
				}
			}

			// build rule output message
			rule.output = r.output;
			if (r.source == falco_common::syscall_source)
			{
				apply_output_substitutions(cfg, rule.output);
			}

			THROW(!is_format_valid(cfg.engine, r.source, rule.output, err),
				"Invalid output format '" + rule.output + "': '" + err + "'");

			// construct rule definition and compile it to a filter
			rule.name = r.name;
			rule.source = r.source;
			rule.description = r.desc;
			rule.priority = r.priority;
			rule.tags = r.tags;
			try
			{
				auto rule_id = out.insert(rule, rule.name);
				out.at(rule_id)->id = rule_id;
				source->ruleset->add(*out.at(rule_id), ast);
				source->ruleset->enable(rule.name, false, r.enabled);
			}
			catch (falco_exception& e)
			{
				string err = e.what();
				if (err.find("nonexistent field") != string::npos
					&& r.skip_if_unknown_filter)
				{
					cfg.warnings.push_back(
						"Rule " + rule.name + ": warning (unknown-field):");
					continue;
				}
				else
				{
					throw falco_exception("Rule " + rule.name + ": error " + err);
				}
			}

			// populate set of event types and emit an special warning
			set<uint16_t> evttypes = { ppm_event_type::PPME_PLUGINEVENT_E };
			if(rule.source == falco_common::syscall_source)
			{
				evttypes.clear();
				filter_evttype_resolver().evttypes(ast, evttypes);
				if ((evttypes.empty() || evttypes.size() > 100)
					&& r.warn_evttypes)
				{
					cfg.warnings.push_back(
						"Rule " + rule.name + ": warning (no-evttype):\n" +
						+ "    matches too many evt.type values.\n"
						+ "    This has a significant performance penalty.");
				}
			}
		}
		catch (exception& e)
		{
			throw falco_exception(r.ctx.error(e.what()));
		}
	}
}

bool rule_loader::compile(configuration& cfg, indexed_vector<falco_rule>& out)
{
	indexed_vector<list_info> lists;
	indexed_vector<macro_info> macros;

	// expand all lists, macros, and rules
	try
	{
		compile_list_infos(cfg, lists);
		compile_macros_infos(cfg, lists, macros);
		compile_rule_infos(cfg, lists, macros, out);
	}
	catch (exception& e)
	{
		cfg.errors.push_back(e.what());
		return false;
	}

	// print info on any dangling lists or macros that were not used anywhere
	for (auto &m : macros)
	{
		if (!m.used)
		{
			cfg.warnings.push_back("macro " + m.name
				+ " not referred to by any rule/macro");
		}
	}
	for (auto &l : lists)
	{
		if (!l.used)
		{
			cfg.warnings.push_back("list " + l.name
				+ " not referred to by any rule/macro/list");
		}
	}
	return true;
}
