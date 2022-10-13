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

#include "application.h"

using namespace falco::app;

application::run_result application::load_config()
{
	if (!m_options.conf_filename.empty())
	{
		m_state->config->init(m_options.conf_filename, m_options.cmdline_config_options);
		falco_logger::set_time_format_iso_8601(m_state->config->m_time_format_iso_8601);

		// log after config init because config determines where logs go
		falco_logger::log(LOG_INFO, "Falco version: " + std::string(FALCO_VERSION) + " (" + std::string(FALCO_TARGET_ARCH) + ")\n");
		if (!m_state->cmdline.empty())
		{
			falco_logger::log(LOG_DEBUG, "CLI args: " + m_state->cmdline);
		}
		falco_logger::log(LOG_INFO, "Falco initialized with configuration file: " + m_options.conf_filename + "\n");
	}
	else
	{
#ifndef BUILD_TYPE_RELEASE
		return run_result::fatal(std::string("You must create a config file at ")  + FALCO_SOURCE_CONF_FILE + ", " + FALCO_INSTALL_CONF_FILE + " or by passing -c");
#else
		return run_result::fatal(std::string("You must create a config file at ")  + FALCO_INSTALL_CONF_FILE + " or by passing -c");
#endif
	}

	m_state->config->m_buffered_outputs = !m_options.unbuffered_outputs;

	return run_result::ok();
}
