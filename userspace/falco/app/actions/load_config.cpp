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
#include "falco_utils.h"

using namespace falco::app;
using namespace falco::app::actions;

// applies legacy/in-deprecation options to the current state
static falco::app::run_result apply_deprecated_options(const falco::app::state& s)
{
	return run_result::ok();
}

falco::app::run_result falco::app::actions::load_config(const falco::app::state& s)
{
	// List of loaded conf files, ie: s.options.conf_filename
	// plus all the `config_files` expanded list of configs.
	config_loaded_res res;
	try
	{
		if (!s.options.conf_filename.empty())
		{
			res = s.config->init_from_file(s.options.conf_filename, s.options.cmdline_config_options);
		}
		else
		{
			// Is possible to have an empty config file when we want to use some command line
			// options like `--help`, `--version`, ...
			// The configs used in `load_yaml` will be initialized to the default values.
			res = s.config->init_from_content("", s.options.cmdline_config_options);
		}
	}
	catch (std::exception& e)
	{
		return run_result::fatal(e.what());
	}

	// log after config init because config determines where logs go
	falco_logger::set_time_format_iso_8601(s.config->m_time_format_iso_8601);
	falco_logger::log(falco_logger::level::INFO, "Falco version: " + std::string(FALCO_VERSION) + " (" + std::string(FALCO_TARGET_ARCH) + ")\n");
	if (!s.cmdline.empty())
	{
		falco_logger::log(falco_logger::level::DEBUG, "CLI args: " + s.cmdline);
	}
	if (!s.options.conf_filename.empty())
	{
		falco_logger::log(falco_logger::level::INFO, "Falco initialized with configuration files:\n");
		for (const auto& pair : res)
		{
			auto config_path = pair.first;
			auto validation = pair.second;
			auto priority = validation == yaml_helper::validation_ok ? falco_logger::level::INFO : falco_logger::level::WARNING;
			falco_logger::log(priority, std::string("   ") + config_path + " | schema validation: " + validation + "\n");
		}
	}

	s.config->m_buffered_outputs = !s.options.unbuffered_outputs;

	return apply_deprecated_options(s);
}

falco::app::run_result falco::app::actions::require_config_file(const falco::app::state& s)
{
#ifndef __EMSCRIPTEN__
	if (s.options.conf_filename.empty())
	{
#ifndef BUILD_TYPE_RELEASE
		return run_result::fatal(std::string("You must create a config file at ")  + FALCO_SOURCE_CONF_FILE + ", " + FALCO_INSTALL_CONF_FILE + " or by passing -c");
#else // BUILD_TYPE_RELEASE
		return run_result::fatal(std::string("You must create a config file at ")  + FALCO_INSTALL_CONF_FILE + " or by passing -c");
#endif // BUILD_TYPE_RELEASE
	}
#endif // __EMSCRIPTEN__
	return run_result::ok();
}