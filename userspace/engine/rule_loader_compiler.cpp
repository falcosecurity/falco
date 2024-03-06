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
#include <memory>
#include <set>
#include <vector>

#include "rule_loader_compiler.h"
#include "filter_warning_resolver.h"

#define MAX_VISIBILITY		((uint32_t) -1)

#define THROW(cond, err, ctx)    { if ((cond)) { throw rule_loader::rule_load_exception(falco::load_result::LOAD_ERR_VALIDATE, (err), (ctx)); } }

static std::string s_container_info_fmt = "%container.info";
static std::string s_default_extra_fmt  = "container_id=%container.id container_name=%container.name";

using namespace libsinsp::filter;

// todo(jasondellaluce): this breaks string escaping in lists and exceptions
static void quote_item(std::string& e)
{
	if (e.find(" ") != std::string::npos && e[0] != '"' && e[0] != '\'')
	{
		e = '"' + e + '"';
	}
}

static void paren_item(std::string& e)
{
	if(e[0] != '(')
	{
		e = '(' + e + ')';
	}
}

static inline bool is_operator_for_list(const std::string& op)
{
	auto ops = libsinsp::filter::parser::supported_operators(true);
	return find(ops.begin(), ops.end(), op) != ops.end();
}

static bool is_format_valid(const falco_source& source, std::string fmt, std::string& err)
{
	try
	{
		std::shared_ptr<sinsp_evt_formatter> formatter;
		formatter = source.formatter_factory->create_formatter(fmt);
		return true;
	}
	catch(std::exception &e)
	{
		err = e.what();
		return false;
	}
}

static void build_rule_exception_infos(
	const std::vector<rule_loader::rule_exception_info>& exceptions,
	std::set<std::string>& exception_fields,
	std::string& condition)
{
	std::string tmp;
	condition = "(" + condition + ")";
	for (const auto &ex : exceptions)
	{
		std::string icond;
		if(!ex.fields.is_list)
		{
			for (const auto &val : ex.values)
			{
				THROW(val.is_list,
				       "Expected values array to contain a list of strings",
				       ex.ctx)
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
			for (const auto &values : ex.values)
			{
				THROW(ex.fields.items.size() != values.items.size(),
				       "Fields and values lists must have equal length",
				       ex.ctx);
				icond += icond == "(" ? "" : " or ";
				icond += "(";
				uint32_t k = 0;
				std::string istr;
				for (const auto &field : ex.fields.items)
				{
					icond += k == 0 ? "" : " and ";
					if (values.items[k].is_list)
					{
						istr = "(";
						for (const auto &v : values.items[k].items)
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

static inline rule_loader::list_info* list_info_from_name(
	const rule_loader::collector& c, const std::string& name)
{
	auto ret = c.lists().at(name);
	if (!ret)
	{
		throw falco_exception("can't find internal list info at name: " + name);
	}
	return ret;
}

static inline rule_loader::macro_info* macro_info_from_name(
	const rule_loader::collector& c, const std::string& name)
{
	auto ret = c.macros().at(name);
	if (!ret)
	{
		throw falco_exception("can't find internal macro info at name: " + name);
	}
	return ret;
}

// todo(jasondellaluce): this breaks string escaping in lists
static bool resolve_list(std::string& cnd, const falco_list& list)
{
	static std::string blanks = " \t\n\r";
	static std::string delims = blanks + "(),=";
	std::string tmp;
	std::string new_cnd;
	size_t start, end;
	bool used = false;
	start = cnd.find(list.name);
	while (start != std::string::npos)
	{
		// the characters surrounding the name must
		// be delims of beginning/end of string
		end = start + list.name.length();
		if ((start == 0 || delims.find(cnd[start - 1]) != std::string::npos)
			&& (end >= cnd.length() || delims.find(cnd[end]) != std::string::npos))
		{
			// shift pointers to consume all whitespaces
			while (start > 0
				&& blanks.find(cnd[start - 1]) != std::string::npos)
			{
				start--;
			}
			while (end < cnd.length()
				&& blanks.find(cnd[end]) != std::string::npos)
			{
				end++;
			}
			// create substitution string by concatenating all values
			std::string sub = "";
			for (const auto &v : list.items)
			{
				if (!sub.empty())
				{
					sub += ", ";
				}
				tmp = v;
				quote_item(tmp);
				sub += tmp;
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

static inline void resolve_macros(
	filter_macro_resolver& macro_resolver,
	const indexed_vector<rule_loader::macro_info>& infos,
	indexed_vector<falco_macro>& macros,
	std::shared_ptr<ast::expr>& ast,
	const std::string& condition,
	uint32_t visibility,
	const rule_loader::context &ctx)
{
	macro_resolver.clear();
	for (const auto &m : infos)
	{
		if (m.index < visibility)
		{
			auto macro = macros.at(m.name);
			macro_resolver.set_macro(m.name, macro->condition);
		}
	}
	macro_resolver.run(ast);

	// Note: only complaining about the first error or unknown macro
	const auto& errors_macros = macro_resolver.get_errors();
	const auto& unresolved_macros = macro_resolver.get_unknown_macros();
	if(!errors_macros.empty() || !unresolved_macros.empty())
	{
		auto errpos = !errors_macros.empty()
			? errors_macros.begin()->second
			: unresolved_macros.begin()->second;
		std::string errmsg = !errors_macros.empty()
			? errors_macros.begin()->first
			: ("Undefined macro '" + unresolved_macros.begin()->first + "' used in filter.");
		const rule_loader::context cond_ctx(errpos, condition, ctx);
		THROW(true, errmsg, cond_ctx);
	}

	for (const auto &it : macro_resolver.get_resolved_macros())
	{
		macros.at(it.first)->used = true;
	}
}

// note: there is no visibility order between filter conditions and lists
static std::shared_ptr<ast::expr> parse_condition(
	std::string condition,
	indexed_vector<falco_list>& lists,
	const rule_loader::context &ctx)
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
		std::shared_ptr<ast::expr> res_ptr(p.parse());
		return res_ptr;
	}
	catch (const sinsp_exception& e)
	{
		rule_loader::context parsectx(p.get_pos(), condition, ctx);

		throw rule_loader::rule_load_exception(
			falco::load_result::LOAD_ERR_COMPILE_CONDITION,
			e.what(),
			parsectx);
	}
}

static void apply_output_substitutions(
	rule_loader::configuration& cfg,
	std::string& out)
{
	if (out.find(s_container_info_fmt) != std::string::npos)
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

void rule_loader::compiler::compile_list_infos(
		configuration& cfg,
		const collector& col,
		indexed_vector<falco_list>& out) const
{
	std::list<std::string> used_names;
	falco_list infos;
	for (const auto &list : col.lists())
	{
		infos.name = list.name;
		infos.items.clear();
		for (const auto &item : list.items)
		{
			const auto ref = col.lists().at(item);
			if (ref && ref->index < list.visibility)
			{
				used_names.push_back(ref->name);
				for (const auto &val : ref->items)
				{
					infos.items.push_back(val);
				}
			}
			else
			{
				infos.items.push_back(item);
			}
		}
		infos.used = false;
		auto list_id = out.insert(infos, infos.name);
		out.at(list_id)->id = list_id;
	}
	for (const auto &name : used_names)
	{
		out.at(name)->used = true;
	}
}

// note: there is a visibility ordering between macros
void rule_loader::compiler::compile_macros_infos(
		configuration& cfg,
		const collector& col,
		indexed_vector<falco_list>& lists,
		indexed_vector<falco_macro>& out) const
{
	for (const auto &m : col.macros())
	{
		falco_macro entry;
		entry.name = m.name;
		entry.condition = parse_condition(m.cond, lists, m.cond_ctx);
		entry.used = false;
		auto macro_id = out.insert(entry, m.name);
		out.at(macro_id)->id = macro_id;
	}

	filter_macro_resolver macro_resolver;
	for (auto &m : out)
	{
		const auto* info = macro_info_from_name(col, m.name);
		resolve_macros(macro_resolver, col.macros(), out, m.condition, info->cond, info->visibility, info->ctx);
	}
}

static bool err_is_unknown_type_or_field(const std::string& err)
{
	return err.find("nonexistent field") != std::string::npos
		|| err.find("invalid formatting token") != std::string::npos
		|| err.find("unknown event type") != std::string::npos;
}

bool rule_loader::compiler::compile_condition(
	configuration& cfg,
	filter_macro_resolver& macro_resolver,
	indexed_vector<falco_list>& lists,
	const indexed_vector<rule_loader::macro_info>& macros,
	const std::string& condition,
	std::shared_ptr<sinsp_filter_factory> filter_factory,
	const rule_loader::context& cond_ctx,
	const rule_loader::context& parent_ctx,
	bool allow_unknown_fields,
	indexed_vector<falco_macro>& macros_out,
	std::shared_ptr<libsinsp::filter::ast::expr>& ast_out,
	std::shared_ptr<sinsp_filter>& filter_out) const
{
	std::set<falco::load_result::load_result::warning_code> warn_codes;
	filter_warning_resolver warn_resolver;
	ast_out = parse_condition(condition, lists, cond_ctx);
	resolve_macros(macro_resolver, macros, macros_out, ast_out, condition, MAX_VISIBILITY, parent_ctx);

	// check for warnings in the filtering condition
	if(warn_resolver.run(ast_out.get(), warn_codes))
	{
		for(const auto& w : warn_codes)
		{
			cfg.res->add_warning(w, "", parent_ctx);
		}
	}

	// validate the rule's condition: we compile it into a sinsp filter
	// on-the-fly and we throw an exception with details on failure
	sinsp_filter_compiler compiler(filter_factory, ast_out.get());
	try
	{
		filter_out = compiler.compile();
	}
	catch(const sinsp_exception& e)
	{
		// skip the rule silently if skip_if_unknown_filter is true and
		// we encountered some specific kind of errors
		std::string err = e.what();
		if(err_is_unknown_type_or_field(err) && allow_unknown_fields)
		{
			cfg.res->add_warning(
				falco::load_result::load_result::LOAD_UNKNOWN_FILTER,
				err,
				cond_ctx);
			return false;
		}
		rule_loader::context ctx(compiler.get_pos(), condition, cond_ctx);
		throw rule_loader::rule_load_exception(
			falco::load_result::load_result::LOAD_ERR_COMPILE_CONDITION,
			err,
			ctx);
	}

	return true;
}

void rule_loader::compiler::compile_rule_infos(
	configuration& cfg,
	const collector& col,
	indexed_vector<falco_list>& lists,
	indexed_vector<falco_macro>& macros,
	indexed_vector<falco_rule>& out) const
{
	std::string err, condition;
	filter_macro_resolver macro_resolver;
	for(const auto& r : col.rules())
	{
		// skip the rule if it has an unknown source
		if (r.unknown_source)
		{
			continue;
		}

		// note: this should not be nullptr if the source is not unknown
		auto source = cfg.sources.at(r.source);
		THROW(!source,
		      std::string("Unknown source at compile-time") + r.source,
		      r.ctx);

		// build filter AST by parsing the condition, building exceptions,
		// and resolving lists and macros
		falco_rule rule;

		condition = r.cond;
		if (!r.exceptions.empty())
		{
			build_rule_exception_infos(
				r.exceptions, rule.exception_fields, condition);
		}

		// build rule output message
		rule.output = r.output;
		apply_output_substitutions(cfg, rule.output);

		// validate the rule's output
		if(!is_format_valid(*cfg.sources.at(r.source), rule.output, err))
		{
			// skip the rule silently if skip_if_unknown_filter is true and
			// we encountered some specific kind of errors
			if (err_is_unknown_type_or_field(err) && r.skip_if_unknown_filter)
			{
				cfg.res->add_warning(
					falco::load_result::load_result::LOAD_UNKNOWN_FILTER,
					err,
					r.output_ctx);
				continue;
			}
			throw rule_load_exception(
				falco::load_result::load_result::LOAD_ERR_COMPILE_OUTPUT,
				err,
				r.output_ctx);
		}

		if (!compile_condition(cfg,
				  macro_resolver,
				  lists,
				  col.macros(),
				  condition,
				  cfg.sources.at(r.source)->filter_factory,
				  r.cond_ctx,
				  r.ctx,
				  r.skip_if_unknown_filter,
				  macros,
				  rule.condition,
				  rule.filter))
		{
			continue;
		}

		// populate set of event types and emit an special warning
		if(r.source == falco_common::syscall_source)
		{
			auto evttypes = libsinsp::filter::ast::ppm_event_codes(rule.condition.get());
			if ((evttypes.empty() || evttypes.size() > 100) && r.warn_evttypes)
			{
				cfg.res->add_warning(
					falco::load_result::load_result::LOAD_NO_EVTTYPE,
					"Rule matches too many evt.type values. This has a significant performance penalty.",
					r.ctx);
			}
		}

		// finalize the rule definition and add it to output
		rule.name = r.name;
		rule.source = r.source;
		rule.description = r.desc;
		rule.priority = r.priority;
		rule.tags = r.tags;
		auto rule_id = out.insert(rule, rule.name);
		out.at(rule_id)->id = rule_id;
	}
}

std::unique_ptr<rule_loader::compile_output> rule_loader::compiler::new_compile_output()
{
	return std::make_unique<compile_output>();
}

void rule_loader::compiler::compile(
		configuration& cfg,
		const collector& col,
		compile_output& out) const
{
	// expand all lists, macros, and rules
	try
	{
		compile_list_infos(cfg, col, out.lists);
		compile_macros_infos(cfg, col, out.lists, out.macros);
		compile_rule_infos(cfg, col, out.lists, out.macros, out.rules);
	}
	catch(rule_load_exception &e)
	{
		cfg.res->add_error(e.ec, e.msg, e.ctx);
		return;
	}

	// print info on any dangling lists or macros that were not used anywhere
	for (const auto &m : out.macros)
	{
		if (!m.used)
		{
			cfg.res->add_warning(
				falco::load_result::load_result::LOAD_UNUSED_MACRO,
				"Macro not referred to by any other rule/macro",
				macro_info_from_name(col, m.name)->ctx);
		}
	}
	for (const auto &l : out.lists)
	{
		if (!l.used)
		{
			cfg.res->add_warning(
				falco::load_result::LOAD_UNUSED_LIST,
				"List not referred to by any other rule/macro",
				list_info_from_name(col, l.name)->ctx);
		}
	}
}
