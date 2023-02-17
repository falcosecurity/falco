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

#include <string>
#include <memory>
#include <set>
#include <vector>

#include "rule_loader_compiler.h"
#include "filter_macro_resolver.h"
#include "filter_warning_resolver.h"

#define MAX_VISIBILITY		((uint32_t) -1)

#define THROW(cond, err, ctx)    { if ((cond)) { throw rule_loader::rule_load_exception(falco::load_result::LOAD_ERR_VALIDATE, (err), (ctx)); } }

static std::string s_container_info_fmt = "%container.info";
static std::string s_default_extra_fmt  = "%container.name (id=%container.id)";

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

static inline bool is_operator_defined(const std::string& op)
{
	auto ops = libsinsp::filter::parser::supported_operators();
	return find(ops.begin(), ops.end(), op) != ops.end();
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
		std::shared_ptr<gen_event_formatter> formatter;
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
	for (auto &ex : exceptions)
	{
		std::string icond;
		if(!ex.fields.is_list)
		{
			for (auto &val : ex.values)
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
			for (auto &values : ex.values)
			{
				THROW(ex.fields.items.size() != values.items.size(),
				       "Fields and values lists must have equal length",
				       ex.ctx);
				icond += icond == "(" ? "" : " or ";
				icond += "(";
				uint32_t k = 0;
				std::string istr;
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
static bool resolve_list(std::string& cnd, const rule_loader::list_info& list)
{
	static std::string blanks = " \t\n\r";
	static std::string delims = blanks + "(),=";
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
	std::shared_ptr<ast::expr>& ast,
	const std::string& condition,
	uint32_t visibility,
	const rule_loader::context &ctx)
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

	for (auto &it : macro_resolver.get_resolved_macros())
	{
		macros.at(it.first)->used = true;
	}
}

// note: there is no visibility order between filter conditions and lists
static std::shared_ptr<ast::expr> parse_condition(
	std::string condition,
	indexed_vector<rule_loader::list_info>& lists,
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
		indexed_vector<list_info>& out) const
{
	std::string tmp;
	std::vector<std::string> used;
	for (auto &list : col.lists())
	{
		list_info v = list;
		v.items.clear();
		for (auto &item : list.items)
		{
			const auto ref = col.lists().at(item);
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
	for (auto &v : used)
	{
		out.at(v)->used = true;
	}
}

// note: there is a visibility ordering between macros
void rule_loader::compiler::compile_macros_infos(
		configuration& cfg,
		const collector& col,
		indexed_vector<list_info>& lists,
		indexed_vector<macro_info>& out) const
{
	for (auto &m : col.macros())
	{
		macro_info entry = m;
		entry.cond_ast = parse_condition(m.cond, lists, m.cond_ctx);
		entry.used = false;
		out.insert(entry, m.name);
	}

	for (auto &m : out)
	{
		resolve_macros(out, m.cond_ast, m.cond, m.visibility, m.ctx);
	}
}


void rule_loader::compiler::compile_rule_infos(
		configuration& cfg,
		const collector& col,
		indexed_vector<list_info>& lists,
		indexed_vector<macro_info>& macros,
		indexed_vector<falco_rule>& out) const
{
	std::string err, condition;
	std::set<falco::load_result::load_result::warning_code> warn_codes;
	filter_warning_resolver warn_resolver;
	for (auto &r : col.rules())
	{
		// skip the rule if below the minimum priority
		if (r.priority > cfg.min_priority)
		{
			continue;
		}

		auto source = cfg.sources.at(r.source);
		// note: this is not supposed to happen

		THROW(!source,
		      std::string("Unknown source ") + r.source,
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
		auto ast = parse_condition(condition, lists, r.cond_ctx);
		resolve_macros(macros, ast, condition, MAX_VISIBILITY, r.ctx);

		// check for warnings in the filtering condition
		warn_codes.clear();
		if (warn_resolver.run(ast.get(), warn_codes))
		{
			for (auto &w : warn_codes)
			{
				cfg.res->add_warning(w, "", r.ctx);
			}
		}

		// build rule output message
		rule.output = r.output;
		if (r.source == falco_common::syscall_source)
		{
			apply_output_substitutions(cfg, rule.output);
		}

		if(!is_format_valid(*cfg.sources.at(r.source), rule.output, err))
		{
			throw rule_load_exception(
				falco::load_result::load_result::LOAD_ERR_COMPILE_OUTPUT,
				err,
				r.output_ctx);
		}

		// construct rule definition and compile it to a filter
		rule.name = r.name;
		rule.source = r.source;
		rule.description = r.desc;
		rule.priority = r.priority;
		rule.tags = r.tags;

		auto rule_id = out.insert(rule, rule.name);
		out.at(rule_id)->id = rule_id;

		// This also compiles the filter, and might throw a
		// falco_exception with details on the compilation
		// failure.
		sinsp_filter_compiler compiler(cfg.sources.at(r.source)->filter_factory, ast.get());
		try {
			std::shared_ptr<gen_event_filter> filter(compiler.compile());
			source->ruleset->add(*out.at(rule_id), filter, ast);
		}
		catch (const sinsp_exception& e)
		{
			// Allow errors containing "nonexistent field" if
			// skip_if_unknown_filter is true
			std::string err = e.what();

			if (err.find("nonexistent field") != std::string::npos &&
			    r.skip_if_unknown_filter)
			{
				cfg.res->add_warning(
					falco::load_result::load_result::LOAD_UNKNOWN_FIELD,
					e.what(),
					r.cond_ctx);
			}
			else
			{
				rule_loader::context ctx(compiler.get_pos(),
							 condition,
							 r.cond_ctx);

				throw rule_loader::rule_load_exception(
					falco::load_result::load_result::LOAD_ERR_COMPILE_CONDITION,
					e.what(),
					ctx);
			}
		}

		// By default rules are enabled/disabled for the default ruleset
		if(r.enabled)
		{
			source->ruleset->enable(rule.name, true, cfg.default_ruleset_id);
		}
		else
		{
			source->ruleset->disable(rule.name, true, cfg.default_ruleset_id);
		}

		// populate set of event types and emit an special warning
		libsinsp::events::set<ppm_event_code> evttypes = { ppm_event_code::PPME_PLUGINEVENT_E };
		if(rule.source == falco_common::syscall_source)
		{
			evttypes = libsinsp::filter::ast::ppm_event_codes(ast.get());
			if ((evttypes.empty() || evttypes.size() > 100)
			    && r.warn_evttypes)
			{
				cfg.res->add_warning(
					falco::load_result::load_result::LOAD_NO_EVTTYPE,
					"Rule matches too many evt.type values. This has a significant performance penalty.",
					r.ctx);
			}
		}
	}
}

void rule_loader::compiler::compile(
		configuration& cfg,
		const collector& col,
		indexed_vector<falco_rule>& out) const
{
	indexed_vector<list_info> lists;
	indexed_vector<macro_info> macros;

	// expand all lists, macros, and rules
	try
	{
		compile_list_infos(cfg, col, lists);
		compile_macros_infos(cfg, col, lists, macros);
		compile_rule_infos(cfg, col, lists, macros, out);
	}
	catch(rule_load_exception &e)
	{
		cfg.res->add_error(e.ec, e.msg, e.ctx);
		return;
	}

	// print info on any dangling lists or macros that were not used anywhere
	for (auto &m : macros)
	{
		if (!m.used)
		{
			cfg.res->add_warning(
				falco::load_result::load_result::LOAD_UNUSED_MACRO,
				"Macro not referred to by any other rule/macro",
				m.ctx);
		}
	}
	for (auto &l : lists)
	{
		if (!l.used)
		{
			cfg.res->add_warning(
				falco::load_result::LOAD_UNUSED_LIST,
				"List not referred to by any other rule/macro",
				l.ctx);
		}
	}
}
