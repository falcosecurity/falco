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

#include "load_config.h"

namespace falco {
namespace app {

act_load_config::act_load_config(application &app)
	: init_action(app), m_name("load config")
{
}

act_load_config::~act_load_config()
{
}

const std::string &act_load_config::name()
{
	return m_name;
}

const std::list<std::string> &act_load_config::prerequsites()
{
	return m_prerequsites;
}

runnable_action::run_result act_load_config::run()
{
	run_result ret = {true, "", true};

	if (options().conf_filename.size())
	{
		state().config->init(options().conf_filename, options().cmdline_config_options);
		falco_logger::set_time_format_iso_8601(state().config->m_time_format_iso_8601);

		// log after config init because config determines where logs go
		falco_logger::log(LOG_INFO, "Falco version " + std::string(FALCO_VERSION) + " (driver version " + std::string(DRIVER_VERSION) + ")\n");
		falco_logger::log(LOG_INFO, "Falco initialized with configuration file " + options().conf_filename + "\n");
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

	state().config->m_buffered_outputs = !options().unbuffered_outputs;

	return ret;
}

}; // namespace application
}; // namespace falco

