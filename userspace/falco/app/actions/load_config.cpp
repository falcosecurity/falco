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

// applies legacy/in-deprecation options to the current config
static void apply_deprecated_options(
		const falco::app::options& opts,
		const std::shared_ptr<falco_configuration>& cfg)
{
	if (!opts.stats_output_file.empty() || !opts.stats_interval.empty())
	{
		falco_logger::log(LOG_WARNING, "Options '-s' and '--stats-interval' will be deprecated in the future, metrics must be configured through config file");
		if (!opts.stats_output_file.empty())
		{
			cfg->m_metrics_enabled = true;
			cfg->m_metrics_output_file = opts.stats_output_file;
			if (!opts.stats_interval.empty())
			{
				cfg->m_metrics_interval_str = opts.stats_interval;
				cfg->m_metrics_interval = falco::utils::parse_prometheus_interval(cfg->m_metrics_interval_str);
			}
		}
	}
}

falco::app::run_result falco::app::actions::load_config(falco::app::state& s)
{
	try
	{
		if (!s.options.conf_filename.empty())
		{
			s.config->init(s.options.conf_filename, s.options.cmdline_config_options);
		}
		else
		{
			s.config->init(s.options.cmdline_config_options);
		}
	}
	catch (std::exception& e)
	{
		return run_result::fatal(e.what());
	}

	// log after config init because config determines where logs go
	falco_logger::set_time_format_iso_8601(s.config->m_time_format_iso_8601);
	falco_logger::log(LOG_INFO, "Falco version: " + std::string(FALCO_VERSION) + " (" + std::string(FALCO_TARGET_ARCH) + ")\n");
	if (!s.cmdline.empty())
	{
		falco_logger::log(LOG_DEBUG, "CLI args: " + s.cmdline);
	}
	if (!s.options.conf_filename.empty())
	{
		falco_logger::log(LOG_INFO, "Falco initialized with configuration file: " + s.options.conf_filename + "\n");
	}

	s.config->m_buffered_outputs = !s.options.unbuffered_outputs;

	apply_deprecated_options(s.options, s.config);

	return run_result::ok();
}

falco::app::run_result falco::app::actions::require_config_file(falco::app::state& s)
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