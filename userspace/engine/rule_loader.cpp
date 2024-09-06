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

#include "rule_loader.h"
#include "yaml_helper.h"


static const std::string item_type_strings[] = {
	"value for",
	"exceptions",
	"exception",
	"exception values",
	"exception value",
	"rules content",
	"rules content item",
	"required_engine_version",
	"required plugin versions",
	"required plugin versions entry",
	"required plugin versions alternative",
	"list",
	"list item",
	"macro",
	"macro condition",
	"rule",
	"rule condition",
	"condition expression",
	"rule output",
	"rule output expression",
	"rule priority",
	"overrides",
	"extension item"
};

const std::string& rule_loader::context::item_type_as_string(enum item_type it)
{
	return item_type_strings[it];
}

rule_loader::context::context(const std::string& name)
{
	// This ensures that every context has one location, even if
	// that location is effectively the whole document.
	location loc = {name, position(), rule_loader::context::RULES_CONTENT, ""};
	m_locs.push_back(loc);
}

rule_loader::context::context(const YAML::Node &item,
			      const item_type item_type,
			      const std::string& item_name,
			      const context& parent)
{
	init(parent.name(), position(item.Mark()), item_type, item_name, parent);
}

rule_loader::context::context(const YAML::Mark &mark, const context& parent)
{
	init(parent.name(), position(mark), item_type::VALUE_FOR, "", parent);
}

rule_loader::context::context(const libsinsp::filter::ast::pos_info& pos,
			      const std::string& condition,
			      const context& parent)
	: alt_content(condition)
{

	// Contexts based on conditions don't use the
	// filename. Instead the "name" is just the condition, and
	// uses a short prefix of the condition.
	std::string condition_name = "\"" + (
		condition.length() > 20
		? condition.substr(0, 20 - 3) + "...\""
		: condition + "\"");
	std::replace(condition_name.begin(), condition_name.end(), '\n', ' ');
	std::replace(condition_name.begin(), condition_name.end(), '\r', ' ');

	std::string item_name = "";

	// Convert the parser position to a context location. Both
	// they have the same basic info (position, line, column).
	// parser line/columns are 1-indexed while yaml marks are
	// 0-indexed, though.
	position condpos;
	auto& lastpos = parent.m_locs.back();
	condpos.pos = pos.idx + lastpos.pos.pos;
	condpos.line = pos.line + lastpos.pos.line;
	condpos.column = pos.col + lastpos.pos.column;

	init(condition_name, condpos, rule_loader::context::CONDITION_EXPRESSION, item_name, parent);
}

const std::string& rule_loader::context::name() const
{
	// All valid contexts should have at least one location.
	if(m_locs.empty())
	{
		throw falco_exception("rule_loader::context without location?");
	}

	return m_locs.front().name;
}

void rule_loader::context::init(const std::string& name,
				const position& pos,
				const item_type item_type,
				const std::string& item_name,
				const context& parent)
{
	// Copy parent locations
	m_locs = parent.m_locs;

	// Add current item to back
	location loc = {name, pos, item_type, item_name};
	m_locs.push_back(loc);
}

std::string rule_loader::context::as_string()
{
	std::ostringstream os;

	// All valid contexts should have at least one location.
	if(m_locs.empty())
	{
		throw falco_exception("rule_loader::context without location?");
	}

	bool first = true;

	for(const auto& loc : m_locs)
	{
		os << (first ? "In " : "    ");
		first = false;

		os << item_type_as_string(loc.item_type);
		if(!loc.item_name.empty())
		{
			os << " '" << loc.item_name << "'";
		}
		os << ": ";

		os << "("
		   << loc.name << ":"
		   << loc.pos.line << ":"
		   << loc.pos.column
		   << ")" << std::endl;
	}

	return os.str();
}

nlohmann::json rule_loader::context::as_json()
{
	nlohmann::json ret;

	ret["locations"] = nlohmann::json::array();

	// All valid contexts should have at least one location.
	if(m_locs.empty())
	{
		throw falco_exception("rule_loader::context without location?");
	}

	for(const auto& loc : m_locs)
	{
		nlohmann::json jloc, jpos;

		jloc["item_type"] = item_type_as_string(loc.item_type);
		jloc["item_name"] = loc.item_name;

		jpos["name"] = loc.name;
		jpos["line"] = loc.pos.line;
		jpos["column"] = loc.pos.column;
		jpos["offset"] = loc.pos.pos;

		jloc["position"] = jpos;

		ret["locations"].push_back(jloc);
	}

	return ret;
}

std::string rule_loader::context::snippet(const falco::load_result::rules_contents_t& rules_contents,
					  size_t snippet_width) const
{
	// All valid contexts should have at least one location.
	if(m_locs.empty())
	{
		throw falco_exception("rule_loader::context without location?");
	}

	rule_loader::context::location loc = m_locs.back();
	auto it = rules_contents.find(loc.name);

	if(alt_content.empty() && it == rules_contents.end())
	{
		return "<No context for file + " + loc.name + ">\n";
	}

	// If not using alt content, the last location's name must be found in rules_contents
	const std::string& snip_content = (!alt_content.empty() ? alt_content : it->second.get());

	if(snip_content.empty())
	{
		return "<No context available>\n";
	}

	// In some cases like this, where the content ends with a
	// dangling property value:
	//   tags:
	// The YAML::Mark position can be past the end of the file.
	size_t pos = loc.pos.pos;
	for(; pos > 0 && (pos >= snip_content.size() || snip_content.at(pos) == '\n'); pos--);

	// The snippet is generally the line that contains the
	// position. So walk backwards from pos to the preceding
	// newline, and walk forwards from pos to the following
	// newline.
	//
	// However, some lines can be very very long, so the walk
	// forwards/walk backwards is capped at a maximum of
	// snippet_width/2 characters in either direction.
	size_t from = pos;
	for(; from > 0 && snip_content.at(from) != '\n' && (pos - from) < (snippet_width/2); from--);

	size_t to = pos;
	for(; to < snip_content.size()-1 && snip_content.at(to) != '\n' && (to - pos) < (snippet_width/2); to++);

	// Don't include the newlines
	if(from < snip_content.size() && snip_content.at(from) == '\n')
	{
		from++;
	}
	if(to < snip_content.size() && snip_content.at(to) == '\n')
	{
		to--;
	}

	std::string ret = snip_content.substr(from, to-from+1);

	if(ret.empty())
	{
		return "<No context available>\n";
	}

	// Replace the initial/end characters with '...' if the walk
	// forwards/backwards was incomplete
	if(pos - from >= (snippet_width/2))
	{
		ret.replace(0, 3, "...");
	}

	if(to - pos >= (snippet_width/2))
	{
		ret.replace(ret.size()-3, 3, "...");
	}

	ret += "\n";

	// Add a blank line with a marker at the position within the snippet
	if(pos-from <= ret.size() - 1)
	{
		ret += std::string(pos-from, ' ') + '^' + "\n";
	}

	return ret;
}

rule_loader::result::result(const std::string &name)
	: name(name),
	  success(true),
	  schema_validation_str(yaml_helper::validation_none)
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

std::string rule_loader::result::schema_validation()
{
	return schema_validation_str;
}

void rule_loader::result::add_error(load_result::error_code ec, const std::string& msg, const context& ctx)
{
	error err = {ec, msg, ctx};
	success = false;

	errors.push_back(err);
}

void rule_loader::result::add_warning(load_result::warning_code wc, const std::string& msg, const context& ctx)
{
	warning warn = {wc, msg, ctx};

	warnings.push_back(warn);
}

void rule_loader::result::set_schema_validation_status(const std::string& status)
{
	schema_validation_str = status;
}

const std::string& rule_loader::result::as_string(bool verbose, const rules_contents_t& contents)
{
	if(verbose)
	{
		return as_verbose_string(contents);
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

	if(success)
	{
		os << "Ok";

		if (!warnings.empty())
		{
			os << ", with warnings";
		}
	}
	else
	{
		os << "Invalid";
	}

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

const std::string& rule_loader::result::as_verbose_string(const rules_contents_t& contents)
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

	if(success)
	{
		os << "Ok";

		if (!warnings.empty())
		{
			os << ", with warnings";
		}
	}
	else
	{
		os << "Invalid";
	}

	if (!errors.empty())
	{
		os << std::endl;

		os << errors.size()
		   << " Errors:" << std::endl;

		for(auto &err : errors)
		{
			os << err.ctx.as_string();

			os << "------" << std::endl;
			os << err.ctx.snippet(contents);
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
			os << warn.ctx.snippet(contents);
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

const nlohmann::json& rule_loader::result::as_json(const rules_contents_t& contents)
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
		jerr["context"]["snippet"] = err.ctx.snippet(contents);

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
		jwarn["context"]["snippet"] = warn.ctx.snippet(contents);

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
	: ctx(ctx), index(0), visibility(0)
{
}

rule_loader::macro_info::macro_info(context &ctx)
	: ctx(ctx), cond_ctx(ctx), index(0), visibility(0)
{
}

rule_loader::rule_exception_info::rule_exception_info(context &ctx)
	: ctx(ctx)
{
}

rule_loader::rule_info::rule_info(context &ctx)
	: ctx(ctx), cond_ctx(ctx), output_ctx(ctx), index(0), visibility(0),
	  unknown_source(false), priority(falco_common::PRIORITY_DEBUG),
	  enabled(true), warn_evttypes(true), skip_if_unknown_filter(false)
{
}

rule_loader::rule_update_info::rule_update_info(context &ctx)
	: ctx(ctx), cond_ctx(ctx)
{
}

rule_loader::rule_load_exception::rule_load_exception(falco::load_result::error_code ec, const std::string& msg, const context& ctx)
	: ec(ec), msg(msg), ctx(ctx)
{
}

rule_loader::rule_load_exception::~rule_load_exception()
{
}

const char* rule_loader::rule_load_exception::what() const noexcept
{
	// const + noexcept: can't use functions that change the object or throw
	return msg.c_str();
}
