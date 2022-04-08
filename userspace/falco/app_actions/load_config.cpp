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
	run_result ret;

	if (m_options.conf_filename.size())
	{
		m_state->config->init(m_options.conf_filename, m_options.cmdline_config_options);
		falco_logger::set_time_format_iso_8601(m_state->config->m_time_format_iso_8601);

		// log after config init because config determines where logs go
		falco_logger::log(LOG_INFO, "Falco version " + std::string(FALCO_VERSION) + " (driver version " + std::string(DRIVER_VERSION) + ")\n");
		falco_logger::log(LOG_INFO, "Falco initialized with configuration file " + m_options.conf_filename + "\n");
	}
	else
	{
		ret.success = false;
		ret.proceed = false;

#ifndef BUILD_TYPE_RELEASE
		ret.errstr = std::string("You must create a config file at ")  + FALCO_SOURCE_CONF_FILE + ", " + FALCO_INSTALL_CONF_FILE + " or by passing -c";
#else
		ret.errstr = std::string("You must create a config file at ")  + FALCO_INSTALL_CONF_FILE + " or by passing -c";
#endif
	}

	m_state->config->m_buffered_outputs = !m_options.unbuffered_outputs;

	return ret;
}
