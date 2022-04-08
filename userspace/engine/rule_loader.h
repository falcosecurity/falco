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
		\brief Erases the internal states and all the loaded rules
	*/
	virtual void clear();

	/*!
		\brief Returns the rules loaded after the last invocation of load()
	*/
	virtual const indexed_vector<falco_rule>& rules();

	/*!
		\brief Configures the loader. The changes will influence the next
		invocation of load().
		\param min_priority The minimum priority below which rules are skipped
		by the loader
		\param extra Text to be appended/substituted in the output of all rules
		\param replace_container_info If true, the extra string is used to
		replace the "%container.info" token in rules outputs. If false, the
		"%container.info" token is substituted with a default text and the
		extra string is appended at the end of the rule output. If a rule
		output does not contain "%container.info", then this flag has no effect
		and the extra string is appended at the end of the rule output anyways.
	*/
	virtual void configure(
		falco_common::priority_type min_priority,
		bool replace_container_info,
		const std::string& extra);

	/*!
		\brief Returns true if the given plugin name and version are compatible
		with the loaded rulesets. If false is returned, required_version is
		filled with the required plugin version that didn't match.
	*/
	virtual bool is_plugin_compatible(
		const std::string& name,
		const std::string& version,
		std::string& required_version);

	/*!
		\brief Parses the content of a ruleset. This should be called multiple
		times to load different rulesets. The internal state (e.g. loaded
		rules, plugin version requirements, etc...) gets updated at each
		invocation of the load() method.
		\param content The contents of the ruleset
		\param engine The instance of falco_engine used to add rule filters
		\param warnings Filled-out with warnings
		\param warnings Filled-out with errors
		\return true if the ruleset content is loaded successfully
	*/
	virtual bool load(
		const std::string& content,
		falco_engine* engine,
		std::vector<std::string>& warnings,
		std::vector<std::string>& errors);

private:
	typedef pair<
		YAML::Node,
		shared_ptr<libsinsp::filter::ast::expr>
	> macro_node;

	bool read(
		const std::string& content, falco_engine* engine,
		std::vector<std::string>& warnings, std::vector<std::string>& errors);
	void read_item(
		falco_engine* engine, YAML::Node& item, vector<string>& warnings);
	void read_required_engine_version(
		falco_engine* engine, YAML::Node& item, vector<string>& warnings);
	void read_required_plugin_versions(
		falco_engine* engine, YAML::Node& item, vector<string>& warnings);
	void read_macro(
		falco_engine* engine, YAML::Node& item, vector<string>& warnings);
	void read_list(
		falco_engine* engine, YAML::Node& item, vector<string>& warnings);
	void read_rule(
		falco_engine* engine, YAML::Node& item, vector<string>& warnings);
	void read_rule_exceptions(
		falco_engine* engine, YAML::Node& item, bool append);
	bool expand(falco_engine* engine,
		std::vector<std::string>& warnings, std::vector<std::string>& errors);
	void expand_list_infos(
		std::map<string, bool>& used, indexed_vector<YAML::Node>& out);
	void expand_macro_infos(
		const indexed_vector<YAML::Node>& lists,
		std::map<string, bool>& used_lists,
		std::map<string, bool>& used_macros,
		indexed_vector<macro_node>& out);
	void expand_rule_infos(
		falco_engine* engine,
		const indexed_vector<YAML::Node>& lists,
		const indexed_vector<macro_node>& macros,
		std::map<string, bool>& used_lists,
		std::map<string, bool>& used_macros,
		vector<string>& warnings);
	void apply_output_substitutions(std::string& output);

	uint32_t m_cur_index;
	std::string m_extra;
	bool m_replace_container_info;
	falco_common::priority_type m_min_priority;
	indexed_vector<falco_rule> m_rules;
	indexed_vector<YAML::Node> m_rule_infos;
	indexed_vector<YAML::Node> m_macro_infos;
	indexed_vector<YAML::Node> m_list_infos;
	std::map<std::string, std::set<std::string>> m_required_plugin_versions;
};
