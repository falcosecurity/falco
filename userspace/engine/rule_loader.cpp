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
#include "rule_loader.h"
#include "filter_macro_resolver.h"

#define MAX_VISIBILITY	  ((uint32_t) -1)
#define THROW(cond, err)	{ if (cond) { throw falco_exception(err); } }

static string s_container_info_fmt = "%container.info";
static string s_default_extra_fmt  = "%container.name (id=%container.id)";

using namespace std;
using namespace libsinsp::filter;

string ctxerr(std::string ctx, std::string e)
{
	e += "\n---\n";
	e += trim(ctx);
	e += "\n---";
	return e;
}

// todo(jasondellaluce): this breaks string escaping in lists and exceptions
static void quote_item(string& e)
{
	if (e.find(" ") != string::npos && e[0] != '"' && e[0] != '\'')
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

static bool is_field_defined(falco_engine *engine, string source, string field)
{
	auto factory = engine->get_filter_factory(source);
	if(factory)
	{
		auto *chk = factory->new_filtercheck(field.c_str());
		if (chk)
		{
			delete(chk);
			return true;
		}
	}
	return false;
}

// todo: this should be in libsinsp
static bool is_operator_defined(std::string op)
{
	static vector<string> ops = {"=", "==", "!=", "<=", ">=", "<", ">",
		"contains", "icontains", "bcontains", "glob", "bstartswith",
		"startswith", "endswith", "in", "intersects", "pmatch"};
	return find(ops.begin(), ops.end(), op) != ops.end();
}

// todo: this should be in libsinsp
static bool is_operator_for_list(std::string op)
{
	return op == "in" || op == "intersects" || op == "pmatch";
}

static bool is_format_valid(falco_engine* e, string src, string fmt, string& err)
{
	try
	{
		shared_ptr<gen_event_formatter> formatter;
		formatter = e->create_formatter(src, fmt);
		return true;
	}
	catch(exception &e)
	{
		err = e.what();
		return false;
	}
}

static string yaml_format_object(
		const string& content,
		const vector<YAML::Node>& docs,
		vector<YAML::Node>::iterator doc,
		YAML::iterator node)
{
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
	string obj = content.substr(from, to - from);
	return trim(obj);
}

template <typename T>
static bool yaml_is_type(const YAML::Node& v)
{
	T t;
	return v.IsDefined() && v.IsScalar() && YAML::convert<T>::decode(v, t);
}

template <typename T>
static void yaml_decode_seq(const YAML::Node& item, vector<T>& out)
{
	T value;
	for(const YAML::Node& v : item)
	{
		THROW(!v.IsScalar() || !YAML::convert<T>::decode(v, value),
			"Can't decode YAML sequence value");
		out.push_back(value);
	}
}

template <typename T>
static void yaml_decode_seq(const YAML::Node& item, set<T>& out)
{
	T value;
	for(const YAML::Node& v : item)
	{
		THROW(!v.IsScalar() || !YAML::convert<T>::decode(v, value),
			"Can't decode YAML sequence value");
		out.insert(value);
	}
}

// todo(jasondellaluce): this breaks string escaping in lists
static bool resolve_list(string& cnd, YAML::Node& list)
{
	static string blanks = " \t\n\r";
	static string delims = blanks + "(),=";
	string new_cnd;
	size_t start, end;
	bool used = false;
	start = cnd.find(list["list"].as<string>());
	while (start != string::npos)
	{
		// the characters surrounding the name must
		// be delims of beginning/end of string
		end = start + list["list"].as<string>().length();
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
			for (auto v : list["items"])
			{
				if (!sub.empty())
				{
					sub += ", ";
				}
				sub += v.as<string>();
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
		start = cnd.find(list["list"].as<string>(), start + 1);
	}
	return used;
}

static void resolve_macros(
	indexed_vector<pair<YAML::Node,shared_ptr<ast::expr>>>& macros,
	map<string, bool>& used_macros,
	shared_ptr<ast::expr>& ast,
	uint32_t index_visibility,
	string on_unknown_err_prefix)
{
	filter_macro_resolver macro_resolver;
	
	for (auto &ref : macros)
	{
		if (ref.first["index"].as<uint32_t>() < index_visibility)
		{
			macro_resolver.set_macro(ref.first["macro"].as<string>(), ref.second);
		}
	}
	macro_resolver.run(ast);
	THROW(!macro_resolver.get_unknown_macros().empty(), on_unknown_err_prefix
		+ "Undefined macro '" + *macro_resolver.get_unknown_macros().begin()
		+ "' used in filter.");
	for (auto &resolved : macro_resolver.get_resolved_macros())
	{
		used_macros[resolved] = true;
	}
}

// note: there is no visibility order between filter conditions and lists
static shared_ptr<ast::expr> parse_condition(string cnd,
	std::map<string, bool>& used_lists, indexed_vector<YAML::Node>& lists)
{
	for (auto &l : lists)
	{
		if (resolve_list(cnd, l))
		{
			used_lists[l["list"].as<string>()] = true;
		}
	}
	libsinsp::filter::parser p(cnd);
	p.set_max_depth(1000);
	try
	{
		shared_ptr<ast::expr> res_ptr(p.parse());
		return res_ptr;
	}
	catch (const sinsp_exception& e)
	{
		throw falco_exception("Compilation error when compiling \"" 
			+ cnd + "\": " + to_string(p.get_pos().col) + ": " + e.what());
	}
}

static shared_ptr<gen_event_filter> compile_condition(
		falco_engine* engine, uint32_t id, shared_ptr<ast::expr> cnd,
		string src, string& err)
{
	try
	{
		auto factory = engine->get_filter_factory(src);
		sinsp_filter_compiler compiler(factory, cnd.get());
		compiler.set_check_id(id);
		shared_ptr<gen_event_filter> ret(compiler.compile());
		return ret;
	}
	catch (const sinsp_exception& e)
	{
		err = e.what();
	}
	catch (const falco_exception& e)
	{
		err = e.what();
	}
	return nullptr;
}

static void define_info(indexed_vector<YAML::Node>& infos,
	YAML::Node& item, string name, uint32_t id)
{
	auto prev = infos.at(name);
	if (prev)
	{
		item["index"] = (*prev)["index"];
		item["index_visibility"] = id;
		(*prev) = item;
	}
	else
	{
		item["index"] = id;
		item["index_visibility"] = id;
		infos.insert(item, name);
	}
}

static void append_infos(YAML::Node& item, YAML::Node& append, uint32_t id)
{
	item["index_visibility"] = id;
	item["context"] = item["context"].as<string>()
		+ "\n\n" + append["context"].as<string>();
}

static void validate_rule_exception(
		falco_engine* engine, YAML::Node& ex, string source)
{
	switch (ex["fields"].Type())
	{
		case YAML::NodeType::Scalar:
			if (!ex["comps"].IsDefined())
			{
				ex["comps"] = "in";
			}
			else
			{
				THROW(!yaml_is_type<string>(ex["fields"])
					|| !yaml_is_type<string>(ex["comps"]),
					"Rule exception item " + ex["name"].as<string>() 
						+ ": fields and comps must both be strings");
			}
			THROW(!is_field_defined(
				engine, source, ex["fields"].as<string>()),
				"Rule exception item " + ex["name"].as<string>()
					+ ": field name " + ex["fields"].as<string>()
					+ " is not a supported filter field");
			THROW(!is_operator_defined(ex["comps"].as<string>()),
				"Rule exception item "  + ex["name"].as<string>()
				+ ": comparison operator " + ex["comps"].as<string>()
				+ " is not a supported comparison operator");
			break;
		case YAML::NodeType::Sequence:
			if (!ex["comps"].IsDefined())
			{
				ex["comps"] = vector<string>();
				for (size_t i = 0; i < ex["fields"].size(); i++)
				{
					ex["comps"].push_back("=");
				}
			}
			else
			{
				THROW(ex["fields"].size() != ex["comps"].size(),
					"Rule exception item " + ex["name"].as<string>()
						+ ": fields and comps lists must have equal length");
			}
			for (auto field : ex["fields"])
			{
				THROW(!yaml_is_type<string>(field),
					"Rule exception item " + ex["name"].as<string>() + ": fields must strings ");
				THROW(!is_field_defined(engine, source, field.as<string>()),
					"Rule exception item " + ex["name"].as<string>() + ": field name "
						+ field.as<string>() + " is not a supported filter field");
			}
			for (auto comp : ex["comps"])
			{
				THROW(!yaml_is_type<string>(comp),
					"Rule exception item " + ex["name"].as<string>() 
					+ ": comps must strings ");
				THROW(!is_operator_defined(comp.as<string>()),
					"Rule exception item " + ex["name"].as<string>() 
					+ ": comparison operator " + comp.as<string>()
					+ " is not a supported comparison operator");
			}
			break;
		default:
			throw falco_exception(
				"Rule exception fields must be a sequence or a string");
	}
}

static void build_rule_exception_infos(
	YAML::Node exceptions, set<string>& exception_fields, string& condition)
{
	for (auto ex : exceptions)
	{
		string icond;
		string value;
		string exname = ex["name"].as<string>();
		if(ex["fields"].IsScalar())
		{
			for (auto val : ex["values"])
			{
				THROW(!yaml_is_type<string>(val),
					"Expected values array for item "
					+ exname + " to contain a list of strings");
				icond += icond.empty()
					? "(" + ex["fields"].as<string>() + " "
						+ ex["comps"].as<string>() + " ("
					: ", ";
				exception_fields.insert(ex["fields"].as<string>());
				value = val.as<string>();
				quote_item(value);
				icond += value;
			}
			icond += icond.empty() ? "" : "))";
		}
		else
		{
			icond = "(";
			for (auto values : ex["values"])
			{
				THROW(ex["fields"].size() != values.size(),
					"Exception item " + exname
					+ ": fields and values lists must have equal length");
				icond += icond == "(" ? "" : " or ";
				icond += "(";
				uint32_t k = 0;
				string istr;
				for (auto field : ex["fields"])
				{
					icond += k == 0 ? "" : " and ";
					if (values[k].IsSequence())
					{
						istr = "(";
						for (auto v : values[k])
						{
							value = v.as<string>();
							quote_item(value);
							istr += istr == "(" ? "" : ", ";
							istr += value;
						}
						istr += ")";
					}
					else
					{
						istr = values[k].as<string>();
						if(is_operator_for_list(ex["comps"][k].as<string>()))
						{
							paren_item(istr);
						}
						else
						{
							quote_item(istr);
						}
					}
					icond += " " + ex["fields"][k].as<string>()
						+ " " + ex["comps"][k].as<string>()
						+ " " + istr;
					exception_fields.insert(ex["fields"][k].as<string>());
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

void rule_loader::clear()
{
	m_cur_index = 0;
	m_rules.clear();
	m_rule_infos.clear();
	m_list_infos.clear();
	m_macro_infos.clear();
	m_required_plugin_versions.clear();
}

indexed_vector<falco_rule>& rule_loader::rules()
{
	return m_rules;
}

void rule_loader::configure(
		falco_common::priority_type min_priority,
		bool replace_container_info,
		const string& extra)
{
	m_extra = extra;
	m_min_priority = min_priority;
	m_replace_container_info = replace_container_info;
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
		for(auto &rversion : it->second)
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

void rule_loader::apply_output_replacements(std::string& out)
{
	if (out.find(s_container_info_fmt) != string::npos)
	{
		if (m_replace_container_info)
		{
			out = replace(out, s_container_info_fmt, m_extra);
			return;
		}
		out = replace(out, s_container_info_fmt, s_default_extra_fmt);
	}
	out += m_extra.empty() ? "" : " " + m_extra;
}

bool rule_loader::load(const string &content, falco_engine* engine,
		vector<string>& warnings, vector<string>& errors)
{
	if (read(content, engine, warnings, errors))
	{
		m_rules.clear();
		engine->clear_filters();
		return expand(engine, warnings, errors);
	}
	return false;
}

bool rule_loader::read(const string &content, falco_engine* engine,
		vector<string>& warnings, vector<string>& errors)
{
	std::vector<YAML::Node> docs;
	try
	{
		docs = YAML::LoadAll(content);
	}
	catch(const exception& e)
	{
		errors.push_back("Could not load YAML file: " + string(e.what()));
		return false;
	}
	
	for (auto doc = docs.begin(); doc != docs.end(); doc++)
	{
		if (doc->IsDefined() && !doc->IsNull())
		{
			if(!doc->IsMap() && !doc->IsSequence())
			{
				errors.push_back("Rules content is not yaml");
				return false;
			}
			if(!doc->IsSequence())
			{
				errors.push_back("Rules content is not yaml array of objects");
				return false;
			}
			for(auto it = doc->begin(); it != doc->end(); it++)
			{
				if (!it->IsNull())
				{
					string ctx = yaml_format_object(content, docs, doc, it);
					YAML::Node item = *it;
					try
					{
						THROW(!item.IsMap(), "Unexpected element type. "
							"Each element should be a yaml associative array.");
						item["context"] = ctx;
						read_item(engine, item, warnings);
					}
					catch(const exception& e)
					{
						errors.push_back(ctxerr(ctx, e.what()));
						return false;
					}
				}
			}
		}
	}
	return true;
}

void rule_loader::read_item(
	falco_engine* engine, YAML::Node& item, vector<string>& warn)
{
	if (item["required_engine_version"].IsDefined())
	{
		read_required_engine_version(engine, item, warn);
	}
	else if(item["required_plugin_versions"].IsDefined())
	{
		read_required_plugin_versions(engine, item, warn);
	}
	else if(item["macro"].IsDefined())
	{
		read_macro(engine, item, warn);
	}
	else if(item["list"].IsDefined())
	{
		read_list(engine, item, warn);
	}
	else if(item["rule"].IsDefined())
	{
		read_rule(engine, item, warn);
	}
	else
	{
		warn.push_back("Unknown top level object");
	}
}

void rule_loader::read_required_engine_version(
	falco_engine* engine, YAML::Node& item, vector<string>& warn)
{
	uint32_t v = 0;
	THROW(!YAML::convert<uint32_t>::decode(item["required_engine_version"], v),
		"Value of required_engine_version must be a number");
	auto engine_ver = falco_engine::engine_version();
	THROW(engine_ver < v, "Rules require engine version " + to_string(v)
		+ ", but engine version is " + to_string(engine_ver));
}

void rule_loader::read_required_plugin_versions(
	falco_engine* engine, YAML::Node& item, vector<string>& warn)
{
	string name, ver;
	THROW(!item["required_plugin_versions"].IsSequence(),
		"Value of required_plugin_versions must be a sequence");
	for(const YAML::Node& plugin : item["required_plugin_versions"])
	{
		THROW(!plugin["name"].IsDefined()
				|| !YAML::convert<string>::decode(plugin["name"], name)
				|| name.empty(),
			"required_plugin_versions item must have name property");
		THROW(!plugin["version"].IsDefined()
				|| !YAML::convert<string>::decode(plugin["version"], ver)
				|| ver.empty(),
			"required_plugin_versions item must have version property");
		m_required_plugin_versions[name].insert(ver);
	}
}

void rule_loader::read_list(
	falco_engine* engine, YAML::Node& item, vector<string>& warn)
{
	string name;
	THROW(!YAML::convert<string>::decode(item["list"], name) || name.empty(),
		"List name is empty");

	THROW(!item["items"].IsDefined() || !item["items"].IsSequence(),
		"List must have property items");

	if(item["append"].IsDefined() && item["append"].as<bool>())
	{
		auto prev = m_list_infos.at(name);
		THROW(!prev, "List " + name +
			" has 'append' key but no list by that name already exists");
		for (auto val : item["items"])
		{
			(*prev)["items"].push_back(val.as<string>());
		}
		append_infos(*prev, item, m_cur_index++);
		return;
	}
	define_info(m_list_infos, item, name, m_cur_index++);
}

void rule_loader::read_macro(
	falco_engine* engine, YAML::Node& item, vector<string>& warn)
{
	string name, cnd;
	THROW(!YAML::convert<string>::decode(item["macro"], name) || name.empty(),
		"Macro name is empty");

	THROW(!item["condition"].IsDefined()
			|| !YAML::convert<string>::decode(item["condition"], cnd)
			|| cnd.empty(),
		"Macro must have property condition");

	if (!yaml_is_type<string>(item["source"])
		|| item["source"].as<string>().empty())
	{
		item["source"] = falco_common::syscall_source;
	}
	if (!engine->is_source_valid(item["source"].as<string>()))
	{
		warn.push_back("Macro " + name
			+ ": warning (unknown-source): unknown source "
			+ item["source"].as<string>() + ", skipping");
		return;
	}

	if(item["append"].IsDefined() && item["append"].as<bool>())
	{
		auto prev = m_macro_infos.at(name);
		THROW(!prev, "Macro " + name
			+ " has 'append' key but no macro by that name already exists");
		(*prev)["condition"] = (*prev)["condition"].as<string>() + " " + cnd;
		append_infos(*prev, item, m_cur_index++);
		return;
	}
	define_info(m_macro_infos, item, name, m_cur_index++);
}

void rule_loader::read_rule(
	falco_engine* engine, YAML::Node& item, vector<string>& warn)
{
	string name;
	falco_common::priority_type priority;
	THROW(!YAML::convert<string>::decode(item["rule"], name) || name.empty(),
		"Rule name is empty");

	auto prev = m_rule_infos.at(name);

	if (!yaml_is_type<bool>(item["skip-if-unknown-filter"]))
	{
		item["skip-if-unknown-filter"] = false;
	}
	if (!yaml_is_type<bool>(item["warn_evttypes"]))
	{
		item["warn_evttypes"] = true;
	}
	if (!yaml_is_type<bool>(item["append"]))
	{
		item["append"] = false;
	}

	if (!yaml_is_type<string>(item["source"])
		|| item["source"].as<string>().empty())
	{
		item["source"] = falco_common::syscall_source;
	}
	if (!engine->is_source_valid(item["source"].as<string>()))
	{
		warn.push_back("Rule " + name
			+ ": warning (unknown-source): unknown source "
			+ item["source"].as<string>() + ", skipping");
		return;
	}
	THROW(prev && (*prev)["source"].as<string>() != item["source"].as<string>(),
		"Rule " + name + " has been re-defined with a different source");

	if (item["append"].as<bool>())
	{
		THROW(!prev, "Rule " + name
			+ " has 'append' key but no rule by that name already exists");
		THROW(!item["condition"].IsDefined() && !item["exceptions"].IsDefined(),
			"Appended rule must have exceptions or condition property");

		if (item["exceptions"].IsDefined())
		{
			read_rule_exceptions(engine, item, true);
		}

		if (item["condition"].IsDefined())
		{
			(*prev)["condition"] = (*prev)["condition"].as<string>()
				+ " " + item["condition"].as<string>();
		}
		append_infos(*prev, item, m_cur_index++);
		return;
	}

	if (!item["condition"].IsDefined() || !item["output"].IsDefined()
		|| !item["desc"].IsDefined() || !item["priority"].IsDefined())
	{
		// we support enabled-only rules
		THROW(!yaml_is_type<bool>(item["enabled"]),
			"Rule must have properties 'condition', 'output', 'desc', and 'priority'");
		auto prev = m_rule_infos.at(name);
		THROW(!prev, "Rule " + name
			+ " has 'enabled' key but no rule by that name already exists");
		(*prev)["enabled"] = item["enabled"].as<bool>();
		return;
	}

	if (!yaml_is_type<bool>(item["enabled"]))
	{
		item["enabled"] = true;
	}

	THROW(!yaml_is_type<string>(item["priority"])
		|| !falco_common::parse_priority(item["priority"].as<string>(), priority),
		"Invalid priority");
	item["priority_num"] = (uint32_t) priority;

	string output = item["output"].as<string>();
	item["output"] = trim(output);

	if (item["exceptions"].IsDefined())
	{
		read_rule_exceptions(engine, item, false);
	}
   
	define_info(m_rule_infos, item, name, m_cur_index++);
}

void rule_loader::read_rule_exceptions(
		falco_engine* engine, YAML::Node& item, bool append)
{
	string exname;
	string rule = item["rule"].as<string>();
	THROW(!item["exceptions"].IsSequence(), "Rule exceptions must be a sequence");
	for (auto ex : item["exceptions"])
	{
		THROW(!YAML::convert<string>::decode(ex["name"], exname)
			|| exname.empty(), "Rule exception item must have name property");

		if(!ex["values"].IsDefined())
		{
			ex["values"] = vector<string>({});
		}

		if (append)
		{
			bool is_new = true;
			auto prev = m_rule_infos.at(rule);
			YAML::Node prev_ex;
			for (YAML::Node e : (*prev)["exceptions"])
			{
				if (is_new && e["name"].as<string>() == exname)
				{
					prev_ex = e;
					is_new = false;
				}
			}
			if (is_new)
			{
				THROW(!ex["fields"].IsDefined(),
					"Rule exception new item " + exname
						+ ": must have fields property with a list of fields");
				THROW(!ex["values"].IsDefined(),
					"Rule exception new item " + exname
						+ ": must have fields property with a list of values");
				validate_rule_exception(engine, ex, item["source"].as<string>());
				(*prev)["exceptions"].push_back(ex);
			}
			else
			{
				THROW(ex["fields"].IsDefined(),
					"Can not append exception fields to existing rule, only values");
				THROW(ex["comps"].IsDefined(),
					"Can not append exception comps to existing rule, only values");
				for (auto vals : ex["values"])
				{
					prev_ex["values"].push_back(vals);
				}
			}
		}
		else
		{
			THROW(!ex["fields"].IsDefined(),
				"Rule exception item " + exname
					+ ": must have fields property with a list of fields");
			validate_rule_exception(engine, ex, item["source"].as<string>());
		}
	}
}

bool rule_loader::expand(falco_engine* engine,
		vector<std::string>& warnings, vector<std::string>& errors)
{
	indexed_vector<YAML::Node> lists;
	indexed_vector<pair<
		YAML::Node,
		shared_ptr<ast::expr> // todo: maybe remove pair
	>> macros;
	map<string, bool> used_lists;
	map<string, bool> used_macros;
	
	// expand all lists, macros, and rules
	try
	{
		expand_list_infos(used_lists, lists);
		expand_macro_infos(lists, used_lists, used_macros, macros);
		expand_rule_infos(engine, lists, macros, used_lists, used_macros, warnings);
	}
	catch (exception& e)
	{
		errors.push_back(e.what());
		return false;
	}

	// print info on any dangling lists or macros that were not used anywhere
	for (auto &m : macros)
	{
		if (!used_macros[m.first["macro"].as<string>()])
		{
			warnings.push_back("macro " + m.first["macro"].as<string>()
				+ " not referred to by any rule/macro");
		}
	}
	for (auto &l : lists)
	{
		if (!used_lists[l["list"].as<string>()])
		{
			warnings.push_back("list " + l["list"].as<string>()
				+ " not referred to by any rule/macro/list");
		}
	}
	return true;
}

// note: there is a visibility ordering between lists
void rule_loader::expand_list_infos(
	map<string, bool>& used, indexed_vector<YAML::Node>& out)
{
	string value;
	vector<string> values;
	for (auto l : m_list_infos)
	{
		try
		{
			values.clear();
			for (auto item : l["items"])
			{
				value = item.as<string>();
				auto ref = m_list_infos.at(value);
				if (ref && (*ref)["index"].as<uint32_t>() < l["index_visibility"].as<uint32_t>())
				{
					used[value] = true;
					for (auto val : (*ref)["items"])
					{
						value = val.as<string>();
						quote_item(value);
						values.push_back(value);
					}
				}
				else
				{
					quote_item(value);
					values.push_back(value);
				}
			}
			auto new_list = YAML::Clone(l);
			new_list["items"] = values;
			out.insert(new_list, new_list["list"].as<string>());
		}
		catch (exception& e)
		{
			throw falco_exception(ctxerr(l["context"].as<string>(), e.what()));
		}
	}
}

// note: there is a visibility ordering between macros
void rule_loader::expand_macro_infos(
	indexed_vector<YAML::Node>& lists,
	map<string, bool>& used_lists,
	map<string, bool>& used_macros,
	indexed_vector<pair<YAML::Node,shared_ptr<ast::expr>>>& out)
{
	for (auto m : m_macro_infos)
	{
		try
		{
			auto ast = parse_condition(m["condition"].as<string>(), used_lists, lists);
			auto pair = make_pair(m, ast);
			out.insert(pair, m["macro"].as<string>());
		}
		catch (exception& e)
		{
			throw falco_exception(ctxerr(m["context"].as<string>(), e.what()));
		}
	}
	for (auto &m : out)
	{
		try
		{
			resolve_macros(out, used_macros, m.second,
				m.first["index_visibility"].as<uint32_t>(),
				"Compilation error when compiling \""
				+ m.first["condition"].as<string>() + "\": ");
		}
		catch (exception& e)
		{
			throw falco_exception(
				ctxerr(m.first["context"].as<string>(), e.what()));
		}
	}
}

void rule_loader::expand_rule_infos(
	falco_engine* engine,
	indexed_vector<YAML::Node>& lists,
	indexed_vector<pair<YAML::Node,shared_ptr<ast::expr>>>& macros,
	map<string, bool>& used_lists,
	map<string, bool>& used_macros,
	vector<string>& warn)
{
	string err;
	for (auto r : m_rule_infos)
	{
		try
		{
			uint32_t priority = r["priority_num"].as<uint32_t>();
			if ((falco_common::priority_type) priority > m_min_priority)
			{
				continue;
			}
		
			set<string> exception_fields;
			string condition = r["condition"].as<string>();
			if (r["exceptions"].IsDefined())
			{
				build_rule_exception_infos(
					r["exceptions"], exception_fields, condition);
			}

			auto ast = parse_condition(condition, used_lists, lists);
		
			resolve_macros(macros, used_macros, ast, MAX_VISIBILITY, "");

			string output = r["output"].as<string>();
			if (r["source"].as<string>() == falco_common::syscall_source)
			{
				apply_output_replacements(output);
			}

			THROW(!is_format_valid(engine, r["source"].as<string>(), output, err), 
				"Invalid output format '" + output + "': '" + err + "'");
			
			falco_rule rule;
			rule.name = r["rule"].as<string>();
			rule.source = r["source"].as<string>();
			rule.description = r["desc"].as<string>();
			rule.output = output;
			rule.priority = (falco_common::priority_type) priority;
			rule.exception_fields = exception_fields;
			yaml_decode_seq<string>(r["tags"], rule.tags);

			auto rule_id = m_rules.insert(rule, rule.name);
			auto filter = compile_condition(engine, rule_id, ast, rule.source, err);
			if (!filter)
			{
				if (r["skip-if-unknown-filter"].as<bool>()
					&& err.find("nonexistent field") != string::npos)
				{
					warn.push_back(
						"Rule " + rule.name + ": warning (unknown-field):");
					continue;
				}
				else
				{
					throw falco_exception("Rule " + rule.name + ": error " + err);
				}
			}
			engine->add_filter(filter, rule.name, rule.source, rule.tags);
			if (rule.source == falco_common::syscall_source
				&& r["warn_evttypes"].as<bool>())
			{
				auto evttypes = filter->evttypes();
				if (evttypes.size() == 0 || evttypes.size() > 100)
				{
					warn.push_back(
						"Rule " + rule.name + ": warning (no-evttype):\n" +
						+ "		 matches too many evt.type values.\n"
						+ "		 This has a significant performance penalty.");
				}
			}
			engine->enable_rule(rule.name, r["enabled"].as<bool>());
		}
		catch (exception& e)
		{
			throw falco_exception(ctxerr(r["context"].as<string>(), e.what()));
		}
	}
}