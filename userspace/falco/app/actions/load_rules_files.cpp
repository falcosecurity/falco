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

#include "actions.h"
#include "helpers.h"
#include "falco_utils.h"

#include <libsinsp/plugin_manager.h>

#include <unordered_set>

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::load_rules_files(falco::app::state& s)
{
	std::string all_rules;

	if (!s.options.rules_filenames.empty())
	{
		s.config->m_rules_filenames = s.options.rules_filenames;
	}

	if(s.config->m_rules_filenames.empty())
	{
		return run_result::fatal("You must specify at least one rules file/directory via -r or a rules_file entry in falco.yaml");
	}

	falco_logger::log(falco_logger::level::DEBUG, "Configured rules filenames:\n");
	for (const auto& path : s.config->m_rules_filenames)
	{
		falco_logger::log(falco_logger::level::DEBUG, std::string("   ") + path + "\n");
	}

	for (const auto &path : s.config->m_rules_filenames)
	{
		falco_configuration::read_rules_file_directory(path, s.config->m_loaded_rules_filenames, s.config->m_loaded_rules_folders);
	}

	std::vector<std::string> rules_contents;
	falco::load_result::rules_contents_t rc;

	rule_read_res validation_res;
	try {
		validation_res = read_files(s.config->m_loaded_rules_filenames.begin(),
			   s.config->m_loaded_rules_filenames.end(),
			   rules_contents,
			   rc, s.config->m_rule_schema);
	}
	catch(falco_exception& e)
	{
		return run_result::fatal(e.what());
	}

	std::string err = "";
	falco_logger::log(falco_logger::level::INFO, "Loading rules from:\n");
	for(auto &filename : s.config->m_loaded_rules_filenames)
	{
		auto validation = validation_res[filename];
		auto priority = validation == yaml_helper::validation_ok ? falco_logger::level::INFO : falco_logger::level::WARNING;
		falco_logger::log(priority, std::string("   ") + filename + " | schema validation: " + validation + "\n");
		std::unique_ptr<falco::load_result> res;

		res = s.engine->load_rules(rc.at(filename), filename);

		if(!res->successful())
		{
			// Return the summary version as the error
			err = res->as_string(true, rc);
			break;
		}

		if(res->has_warnings())
		{
			falco_logger::log(falco_logger::level::WARNING,res->as_string(true, rc) + "\n");
		}
#if defined(__linux__) and !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__)
		s.config->m_loaded_rules_filenames_sha256sum.insert({filename, falco::utils::calculate_file_sha256sum(filename)});
#endif
	}

	// note: we have an egg-and-chicken problem here. We would like to check
	// plugin requirements before loading any rule, so that we avoid having
	// all the "unknown field XXX" errors caused when a plugin is required but
	// not loaded. On the other hand, we can't check the requirements before
	// loading the rules file, because that's where the plugin dependencies
	// are specified. This issue is visible only for dependencies over extractor
	// plugins, due to the fact that if a source plugin is not loaded, its
	// source will be unknown for the engine and so it will skip loading all of
	// the rules to that source, to finally end up here and return a fatal error
	// due to plugin dependency not satisfied being the actual problem.
	//
	// The long-term solution would be to pass information about all the loaded
	// plugins to the falco engine before or when loading a rules file, so that
	// plugin version checks can be performed properly by the engine, just
	// like it does for the engine version requirement. On the other hand,
	// This also requires refactoring a big chunk of the API and code of the
	// engine responsible of loading rules.
	// 
	// Since we're close to releasing Falco v0.35, the chosen workaround is
	// to first collect any error from the engine, then checking if there is
	// also a version dependency not being satisfied, and give that failure
	// cause priority in case we encounter it. This is indeed not perfect, but
	// suits us for the time being. The non-covered corner case is when
	// the `required_plugin_versions` YAML block is defined after the first
	// rule definition (which is wrong anyways but currently allowed by the
	// engine), in which case Falco would stop at the first error (which
	// behavior we'll still want to change in the near future), not collect the
	// plugin deps info, and the checks below will pass with success wrongly.
	//
	// todo(jasondellaluce): perform plugin deps checks inside the
	// falco engine in the middle of the loading procedure of a rules file
	std::string req_err = "";
	if (!check_rules_plugin_requirements(s, req_err))
	{
		err = req_err;
	}

	if (!err.empty())
	{
		return run_result::fatal(err);
	}

	for(const auto& sel : s.config->m_rules_selection)
	{
		bool enable = sel.m_op == falco_configuration::rule_selection_operation::enable;

		if(sel.m_rule != "")
		{
			falco_logger::log(falco_logger::level::INFO,
				(enable ? "Enabling" : "Disabling") + std::string(" rules with name: ") + sel.m_rule + "\n");

			s.engine->enable_rule_wildcard(sel.m_rule, enable);
		}

		if(sel.m_tag != "")
		{
			falco_logger::log(falco_logger::level::INFO,
				(enable ? "Enabling" : "Disabling") + std::string(" rules with tag: ") + sel.m_tag + "\n");

			s.engine->enable_rule_by_tag(std::set<std::string>{sel.m_tag}, enable); // TODO wildcard support
		}
	}

	// printout of `-L` option
	if (s.options.describe_all_rules || !s.options.describe_rule.empty())
	{
		std::string* rptr = !s.options.describe_rule.empty() ? &(s.options.describe_rule) : nullptr;
		const auto& plugins = s.offline_inspector->get_plugin_manager()->plugins();
		auto out = s.engine->describe_rule(rptr, plugins);

		if (!s.config->m_json_output)
		{
			format_described_rules_as_text(out, std::cout);
		}
		else
		{
			std::cout << out.dump() << std::endl;
		}

		return run_result::exit();
	}

	return run_result::ok();
}
