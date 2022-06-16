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
#include <version.h>
#include <sstream>

#define MAX_VISIBILITY		((uint32_t) -1)

#define THROW(cond, err, ctx)    { if ((cond)) { throw rule_loader::rule_load_exception(falco::load_result::LOAD_ERR_VALIDATE, (err), (ctx)); } }

using namespace falco;

static string s_container_info_fmt = "%container.info";
static string s_default_extra_fmt  = "%container.name (id=%container.id)";

using namespace std;
using namespace libsinsp::filter;

rule_loader::context::context(const std::string& name)
	: name(name)
{
}

rule_loader::context::context(const YAML::Node &item,
			      const std::string item_type,
			      const std::string item_name,
			      const context& parent)
	: name(parent.name)
{
	// Copy parent locations
	m_locs = parent.m_locs;

	// Add current item to back
	location loc = {item.Mark(), item_type, item_name};
	m_locs.push_back(loc);
}

std::string rule_loader::context::as_string()
{
	std::ostringstream os;

	// If no locations (can happen for initial file-level
	// context), just note it was somewhere in the file
	if(m_locs.empty())
	{
		os << "In " << name << ":" << std::endl;
		return os.str();
	}

	bool first = true;

	for(auto& loc : m_locs)
	{
		os << (first ? "In " : "    ");
		first = false;

		os << loc.item_type;
		if(!loc.item_name.empty())
		{
			os << " '" << loc.item_name << "'";
		}
		os << ": ";

		os << "("
		   << name << ":"
		   << loc.mark.line << ":"
		   << loc.mark.column
		   << ")" << std::endl;
	}

	return os.str();
}

nlohmann::json rule_loader::context::as_json()
{
	nlohmann::json ret;

	ret["locations"] = nlohmann::json::array();

	if(m_locs.empty())
	{
		nlohmann::json jloc, jpos;

		jloc["item_type"] = "file";
		jloc["item_name"] = "";

		jpos["filename"] = name;
		jpos["line"] = 0;
		jpos["column"] = 0;
		jpos["offset"] = 0;

		jloc["position"] = jpos;

		ret["locations"].push_back(jloc);
	}
	else
	{
		for(auto& loc : m_locs)
		{
			nlohmann::json jloc, jpos;

			jloc["item_type"] = loc.item_type;
			jloc["item_name"] = loc.item_name;

			jpos["filename"] = name;
			jpos["line"] = loc.mark.line;
			jpos["column"] = loc.mark.column;
			jpos["offset"] = loc.mark.pos;

			jloc["position"] = jpos;

			ret["locations"].push_back(jloc);
		}
	}

	return ret;
}

std::string rule_loader::context::snippet(const std::string& content) const
{
	std::string ret;

	if(m_locs.empty() || content.size() == 0)
	{
		return "<No context available>\n";
	}

	rule_loader::context::location loc = m_locs.back();

	size_t from = loc.mark.pos;

	// In some cases like this, where the content ends with a
	// dangling property value:
	//   tags:
	// The YAML::Mark position can be past the end of the file.
	for(; from > 0 && from >= content.size(); from--);

	// Add the line that includes the mark and a marker
	// at the column number.
	size_t to = from;

	for(; from > 0 && content.at(from) != '\n'; from--);
	for(; to < content.size()-1 && content.at(to) != '\n'; to++);

	// Don't include the newlines
	if(content.at(from) == '\n')
	{
		from++;
	}
	if(content.at(to) == '\n')
	{
		to--;
	}

	ret = content.substr(from, to-from+1) + "\n";

	// Add a blank line with a marker at the column number
	ret += std::string(loc.mark.column, ' ') + '^' + "\n";

	return ret;
}

rule_loader::result::result(const std::string &name)
	: name(name),
	  success(true)
{
}

bool rule_loader::result::successful()
{
	return success;
}

bool rule_loader::result::has_warnings()
{
	return (warnings.size() > 0);
}

void rule_loader::result::add_error(load_result::error_code ec, const std::string& msg, const context& ctx, const std::string& rules_content)
{
	error err = {ec, msg, ctx, ctx.snippet(rules_content)};
	success = false;

	errors.push_back(err);
}

void rule_loader::result::add_warning(load_result::warning_code wc, const std::string& msg, const context& ctx, const std::string& rules_content)
{
	warning warn = {wc, msg, ctx, ctx.snippet(rules_content)};

	warnings.push_back(warn);
}

const std::string& rule_loader::result::as_string(bool verbose)
{
	if(verbose)
	{
		return as_verbose_string();
	}
	else
	{
		return as_summary_string();
	}
}

const std::string& rule_loader::result::as_summary_string()
{
	std::ostringstream os;

	if(!res_summary_string.empty())
	{
		return res_summary_string;
	}

	if(!name.empty())
	{
		os << name << ": ";
	}

	os << (success ? "Ok" : "Invalid");

	if(!errors.empty())
	{
		os << std::endl;

		os << " " << errors.size() << " errors: [";
		bool first = true;
		for(auto &err : errors)
		{
			if(!first)
			{
				os << " ";
			}
			first = false;

			os << load_result::error_code_str(err.ec)
			   << " (" << load_result::error_str(err.ec) << ")";
		}
		os << "]";
	}

	if(!warnings.empty())
	{
		os << std::endl;

		os << " " << warnings.size() << " warnings: [";
		bool first = true;
		for(auto &warn : warnings)
		{
			if(!first)
			{
				os << " ";
			}
			first = false;

			os << load_result::warning_code_str(warn.wc)
			   << " (" << load_result::warning_str(warn.wc) << ")";
		}
		os << "]";
	}

	res_summary_string = os.str();
	return res_summary_string;
}

const std::string& rule_loader::result::as_verbose_string()
{
	std::ostringstream os;

	if(!res_verbose_string.empty())
	{
		return res_verbose_string;
	}

	if(!name.empty())
	{
		os << name << ": ";
	}

	os << (success ? "Ok" : "Invalid");

	if (!errors.empty())
	{
		os << std::endl;

		os << errors.size()
		   << " Errors:" << std::endl;

		for(auto &err : errors)
		{
			os << err.ctx.as_string();

			os << "------" << std::endl;
			os << err.snippet;
			os << "------" << std::endl;

			os << load_result::error_code_str(err.ec)
			   << " (" << load_result::error_str(err.ec) << "): "
			   << err.msg
			   << std::endl;
		}
	}
	if (!warnings.empty())
	{
		os << std::endl;

		os << warnings.size()
		   << " Warnings:" << std::endl;

		for(auto &warn : warnings)
		{
			os << warn.ctx.as_string();

			os << "------" << std::endl;
			os << warn.snippet;
			os << "------" << std::endl;

			os << load_result::warning_code_str(warn.wc)
			   << " (" << load_result::warning_str(warn.wc) << "): "
			   << warn.msg;
			os << std::endl;
		}
	}

	res_verbose_string = os.str();
	return res_verbose_string;
}

const nlohmann::json& rule_loader::result::as_json()
{
	nlohmann::json j;

	if(!res_json.empty())
	{
		return res_json;
	}

	j["name"] = name;
	j["successful"] = success;

	j["errors"] = nlohmann::json::array();

	for(auto &err : errors)
	{
		nlohmann::json jerr;

		jerr["context"] = err.ctx.as_json();
		jerr["context"]["snippet"] = err.snippet;

		jerr["code"] = load_result::error_code_str(err.ec);
		jerr["codedesc"] = load_result::error_desc(err.ec);
		jerr["message"] = err.msg;

		j["errors"].push_back(jerr);
	}

	j["warnings"] = nlohmann::json::array();

	for(auto &warn : warnings)
	{
		nlohmann::json jwarn;

		jwarn["context"] = warn.ctx.as_json();
		jwarn["context"]["snippet"] = warn.snippet;

		jwarn["code"] = load_result::warning_code_str(warn.wc);
		jwarn["codedesc"] = load_result::warning_desc(warn.wc);
		jwarn["message"] = warn.msg;

		j["warnings"].push_back(jwarn);
	}

	res_json = j;
	return res_json;
}

rule_loader::engine_version_info::engine_version_info(context &ctx)
	: ctx(ctx)
{
}

rule_loader::plugin_version_info::plugin_version_info()
	: ctx("no-filename-given")
{
}

rule_loader::plugin_version_info::plugin_version_info(context &ctx)
	: ctx(ctx)
{
}

rule_loader::list_info::list_info(context &ctx)
	: ctx(ctx)
{
}

rule_loader::macro_info::macro_info(context &ctx)
	: ctx(ctx), cond_ctx(ctx)
{
}

rule_loader::rule_exception_info::rule_exception_info(context &ctx)
	: ctx(ctx)
{
}

rule_loader::rule_info::rule_info(context &ctx)
	: ctx(ctx), cond_ctx(ctx), output_ctx(ctx)
{
}

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
		       "Fields and comps lists must have equal length",
		       ex.ctx);
		for (auto &v : ex.comps.items)
		{
			THROW(!is_operator_defined(v.item),
			      std::string("'") + v.item + "' is not a supported comparison operator",
			      ex.ctx);
		}
		for (auto &v : ex.fields.items)
		{
			THROW(!source.is_field_defined(v.item),
			      std::string("'") + v.item + "' is not a supported filter field",
			      ex.ctx);
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
		THROW(!source.is_field_defined(ex.fields.item),
		      std::string("'") + ex.fields.item + "' is not a supported filter field",
		      ex.ctx);
	}
}

static void build_rule_exception_infos(
	const vector<rule_loader::rule_exception_info>& exceptions,
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

	// Note: only complaining about the first unknown macro
	THROW(!macro_resolver.get_unknown_macros().empty(),
	      std::string("Undefined macro '")
	      + *macro_resolver.get_unknown_macros().begin()
	      + "' used in filter.",
	      ctx);

	for (auto &m : macro_resolver.get_resolved_macros())
	{
		macros.at(m)->used = true;
	}
}

// note: there is no visibility order between filter conditions and lists
static shared_ptr<ast::expr> parse_condition(
	string condition,
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
		shared_ptr<ast::expr> res_ptr(p.parse());
		return res_ptr;
	}
	catch (const sinsp_exception& e)
	{
		throw rule_loader::rule_load_exception(
			load_result::LOAD_ERR_COMPILE_CONDITION,
			e.what(),
			ctx);
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

const std::map<std::string, std::set<std::string>> rule_loader::required_plugin_versions() const
{
	return m_required_plugin_versions;
}

void rule_loader::define(configuration& cfg, engine_version_info& info)
{
	auto v = falco_engine::engine_version();
	THROW(v < info.version, "Rules require engine version "
	      + to_string(info.version) + ", but engine version is " + to_string(v),
	      info.ctx);
}

void rule_loader::define(configuration& cfg, plugin_version_info& info)
{
	sinsp_version plugin_version(info.version);
	THROW(!plugin_version.m_valid, "Invalid required version '" + info.version
	      + "' for plugin '" + info.name + "'",
	      info.ctx);
	m_required_plugin_versions[info.name].insert(info.version);
}

void rule_loader::define(configuration& cfg, list_info& info)
{
	define_info(m_list_infos, info, m_cur_index++);
}

void rule_loader::append(configuration& cfg, list_info& info)
{
	auto prev = m_list_infos.at(info.name);
	THROW(!prev,
	       "List has 'append' key but no list by that name already exists",
	       info.ctx);
	prev->items.insert(prev->items.end(), info.items.begin(), info.items.end());
	append_info(prev, info, m_cur_index++);
}

void rule_loader::define(configuration& cfg, macro_info& info)
{
	define_info(m_macro_infos, info, m_cur_index++);
}

void rule_loader::append(configuration& cfg, macro_info& info)
{
	auto prev = m_macro_infos.at(info.name);
	THROW(!prev,
	       "Macro has 'append' key but no macro by that name already exists",
	       info.ctx);
	prev->cond += " ";
	prev->cond += info.cond;
	append_info(prev, info, m_cur_index++);
}

void rule_loader::define(configuration& cfg, rule_info& info)
{
	auto source = cfg.sources.at(info.source);
	if (!source)
	{
		cfg.res->add_warning(load_result::LOAD_UNKNOWN_SOURCE,
				     "Unknown source " + info.source + ", skipping",
				     info.ctx,
				     cfg.content);
		return;
	}

	auto prev = m_rule_infos.at(info.name);
	THROW(prev && prev->source != info.source,
	       "Rule has been re-defined with a different source",
	       info.ctx);

	for (auto &ex : info.exceptions)
	{
		THROW(!ex.fields.is_valid(),
		       "Rule exception item must have fields property with a list of fields",
		       ex.ctx);
		validate_exception_info(*source, ex);
	}

	define_info(m_rule_infos, info, m_cur_index++);
}

void rule_loader::append(configuration& cfg, rule_info& info)
{
	auto prev = m_rule_infos.at(info.name);

	THROW(!prev,
	       "Rule has 'append' key but no rule by that name already exists",
	       info.ctx);
	THROW(info.cond.empty() && info.exceptions.empty(),
	       "Appended rule must have exceptions or condition property",
	       info.ctx);

	auto source = cfg.sources.at(prev->source);
	// note: this is not supposed to happen
	THROW(!source,
	      std::string("Unknown source ") + prev->source,
	      info.ctx);

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
			validate_exception_info(*source, ex);
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

void rule_loader::enable(configuration& cfg, rule_info& info)
{
	auto prev = m_rule_infos.at(info.name);
	THROW(!prev,
	       "Rule has 'enabled' key but no rule by that name already exists",
	       info.ctx);
	prev->enabled = info.enabled;
}

rule_loader::rule_load_exception::rule_load_exception(load_result::error_code ec, std::string msg, const context& ctx)
	: ec(ec), msg(msg), ctx(ctx)
{
}

rule_loader::rule_load_exception::~rule_load_exception()
{
}

const char* rule_loader::rule_load_exception::what()
{
	errstr = load_result::error_code_str(ec) + ": "
		+ msg.c_str();

	return errstr.c_str();
}

void rule_loader::compile_list_infos(configuration& cfg, indexed_vector<list_info>& out) const
{
	string tmp;
	vector<string> used;
	for (auto &list : m_list_infos)
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
	for (auto &v : used)
	{
		out.at(v)->used = true;
	}
}

// note: there is a visibility ordering between macros
void rule_loader::compile_macros_infos(
	configuration& cfg,
	indexed_vector<list_info>& lists,
	indexed_vector<macro_info>& out) const
{
	set<string> used;
	for (auto &m : m_macro_infos)
	{
		macro_info entry = m;
		entry.cond_ast = parse_condition(m.cond, lists, m.cond_ctx);
		entry.used = false;
		out.insert(entry, m.name);
	}

	for (auto &m : out)
	{
		resolve_macros(out, m.cond_ast, m.visibility, m.ctx);
	}
}


void rule_loader::compile_rule_infos(
	configuration& cfg,
	indexed_vector<list_info>& lists,
	indexed_vector<macro_info>& macros,
	indexed_vector<falco_rule>& out) const
{
	string err, condition;
	set<load_result::warning_code> warn_codes;
	filter_warning_resolver warn_resolver;
	for (auto &r : m_rule_infos)
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
		resolve_macros(macros, ast, MAX_VISIBILITY, r.ctx);

		// check for warnings in the filtering condition
		warn_codes.clear();
		if (warn_resolver.run(ast.get(), warn_codes))
		{
			for (auto &w : warn_codes)
			{
				cfg.res->add_warning(w, "", r.ctx, cfg.content);
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
				load_result::LOAD_ERR_COMPILE_OUTPUT,
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
		try {
			source->ruleset->add(*out.at(rule_id), ast);
		}
		catch (const falco_exception& e)
		{
			// Allow errors containing "nonexistent field" if
			// skip_if_unknown_filter is true
			std::string err = e.what();

			if (err.find("nonexistent field") != string::npos &&
			    r.skip_if_unknown_filter)
			{
				cfg.res->add_warning(
					load_result::LOAD_UNKNOWN_FIELD,
					e.what(),
					r.cond_ctx,
					cfg.content);
			}
			else
			{
				throw rule_loader::rule_load_exception(
					load_result::LOAD_ERR_COMPILE_CONDITION,
					e.what(),
					r.cond_ctx);
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
		set<uint16_t> evttypes = { ppm_event_type::PPME_PLUGINEVENT_E };
		if(rule.source == falco_common::syscall_source)
		{
			evttypes.clear();
			filter_evttype_resolver().evttypes(ast, evttypes);
			if ((evttypes.empty() || evttypes.size() > 100)
			    && r.warn_evttypes)
			{
				cfg.res->add_warning(
					load_result::LOAD_NO_EVTTYPE,
					"Rule matches too many evt.type values. This has a significant performance penalty.",
					r.ctx,
					cfg.content);
			}
		}
	}
}

void rule_loader::compile(configuration& cfg, indexed_vector<falco_rule>& out) const
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
	catch(rule_load_exception &e)
	{
		cfg.res->add_error(e.ec, e.msg, e.ctx, cfg.content);
	}

	// print info on any dangling lists or macros that were not used anywhere
	for (auto &m : macros)
	{
		if (!m.used)
		{
			cfg.res->add_warning(
				load_result::LOAD_UNUSED_MACRO,
				"Macro not referred to by any other rule/macro",
				m.ctx,
				cfg.content);
		}
	}
	for (auto &l : lists)
	{
		if (!l.used)
		{
			cfg.res->add_warning(
				load_result::LOAD_UNUSED_LIST,
				"List not referred to by any other rule/macro",
				l.ctx,
				cfg.content);
		}
	}
}
