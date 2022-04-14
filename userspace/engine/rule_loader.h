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

#pragma once

#include <map>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>
#include "falco_rule.h"
#include "indexed_vector.h"

// todo(jasondellaluce): remove this cyclic dependency
class falco_engine;


/*!
	\brief Ruleset loader of the falco engine
*/
class rule_loader
{
public:
	/*!
		\brief Represents a section of text from which a certain info
		struct has been decoded
	*/
	struct context
	{
		std::string content;

		/*!
			\brief Wraps an error by adding info about the text section
		*/
		inline std::string error(std::string err)
		{
			err += "\n---\n";
			err += trim(content);
			err += "\n---";
			return err;
		}

		/*!
			\brief Appends another text section info to this one
		*/
		inline void append(context& m)
		{
			content += "\n\n";
			content += m.content;
		}
	};

	/*!
		\brief Contains the info required to load rule definitions
	*/
	struct configuration
	{
		configuration(const std::string& cont): content(cont) {}
		const std::string& content;
		std::string output_extra;
		bool replace_output_container_info;
		falco_common::priority_type min_priority;
		std::vector<std::string> warnings;
		std::vector<std::string> errors;
		falco_engine* engine;
	};

	/*!
		\brief Represents infos about an engine version requirement
	*/
	struct engine_version_info
	{
		uint32_t version;
	};

	/*!
		\brief Represents infos about a plugin version requirement
	*/
	struct plugin_version_info
	{
		std::string name;
		std::string version;
	};

	/*!
		\brief Represents infos about a list 
	*/
	struct list_info
	{
		context ctx;
		bool used;
		size_t index;
		size_t visibility;
		std::string name;
		std::vector<std::string> items;
	};

	/*!
		\brief Represents infos about a macro 
	*/
	struct macro_info
	{
		context ctx;
		bool used;
		size_t index;
		size_t visibility;
		std::string name;
		std::string cond;
		std::string source;
		std::shared_ptr<libsinsp::filter::ast::expr> cond_ast;
	};

	/*!
		\brief Represents infos about a single rule exception
	*/
	struct rule_exception_info
	{
		/*!
			\brief This is necessary due to the dynamic-typed nature of
			exceptions. Each of fields, comps, and values, can either be a
			single value or a list of values. This is a simple hack to make
			this easier to implement in C++, that is not non-dynamic-typed.
		*/
		struct entry {
			bool is_list;
			std::string item;
			std::vector<entry> items;

			inline bool is_valid() const
			{
				return (is_list && !items.empty())
					|| (!is_list && !item.empty());
			}
		};

		std::string name;
		entry fields;
		entry comps;
		std::vector<entry> values;
	};

	/*!
		\brief Represents infos about a rule 
	*/
	struct rule_info
	{
		context ctx;
		size_t index;
		size_t visibility;
		std::string name;
		std::string cond;
		std::string source;
		std::string desc;
		std::string output;
		std::set<std::string> tags;
		std::vector<rule_exception_info> exceptions;
		falco_common::priority_type priority;
		bool enabled;
		bool warn_evttypes;
		bool skip_if_unknown_filter;
	};

	/*!
		\brief Erases all the internal state and definitions
	*/
	virtual void clear();

	/*!
		\brief Returns true if the given plugin name and version are compatible
		with the internal definitions. If false is returned, required_version is
		filled with the required plugin version that didn't match.
	*/
	virtual bool is_plugin_compatible(
		const std::string& name,
		const std::string& version,
		std::string& required_version);
	
	/*!
		\brief Uses the internal state to compile a list of falco_rules
	*/
	bool compile(configuration& cfg, indexed_vector<falco_rule>& out);

	/*!
		\brief Defines an info block. If a similar info block is found
		in the internal state (e.g. another rule with same name), then
		the previous definition gets overwritten
	*/
	virtual void define(configuration& cfg, engine_version_info& info);
	virtual void define(configuration& cfg, plugin_version_info& info);
	virtual void define(configuration& cfg, list_info& info);
	virtual void define(configuration& cfg, macro_info& info);
	virtual void define(configuration& cfg, rule_info& info);

	/*!
		\brief Appends an info block to an existing one. An exception
		is thrown if no existing definition can be matched with the appended
		one
	*/
	virtual void append(configuration& cfg, list_info& info);
	virtual void append(configuration& cfg, macro_info& info);
	virtual void append(configuration& cfg, rule_info& info);

	/*!
		\brief Updates the 'enabled' flag of an existing definition
	*/
	virtual void enable(configuration& cfg, rule_info& info);

private:
	void compile_list_infos(
		configuration& cfg,
		indexed_vector<list_info>& out);
	void compile_macros_infos(
		configuration& cfg,
		indexed_vector<list_info>& lists,
		indexed_vector<macro_info>& out);
	void compile_rule_infos(
		configuration& cfg,
		indexed_vector<list_info>& lists,
		indexed_vector<macro_info>& macros,
		indexed_vector<falco_rule>& out);

	uint32_t m_cur_index;
	indexed_vector<rule_info> m_rule_infos;
	indexed_vector<macro_info> m_macro_infos;
	indexed_vector<list_info> m_list_infos;
	std::map<std::string, std::set<std::string>> m_required_plugin_versions;
};
