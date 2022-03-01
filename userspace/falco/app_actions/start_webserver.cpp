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

#include "start_webserver.h"

#ifndef MINIMAL_BUILD

namespace falco {
namespace app {

act_start_webserver::act_start_webserver(application &app)
	: init_action(app), m_name("start webserver"),
	  m_prerequsites({"init outputs"})
{
}

act_start_webserver::~act_start_webserver()
{
}

const std::string &act_start_webserver::name()
{
	return m_name;
}

const std::list<std::string> &act_start_webserver::prerequsites()
{
	return m_prerequsites;
}

runnable_action::run_result act_start_webserver::run()
{
	run_result ret = {true, "", true};

	if(options().trace_filename.empty() && state().config->m_webserver_enabled && state().enabled_sources.find(application::s_k8s_audit_source) != state().enabled_sources.end())
	{
		std::string ssl_option = (state().config->m_webserver_ssl_enabled ? " (SSL)" : "");
		falco_logger::log(LOG_INFO, "Starting internal webserver, listening on port " + to_string(state().config->m_webserver_listen_port) + ssl_option + "\n");
		m_webserver.init(state().config, state().engine, state().outputs);
		m_webserver.start();
	}

	return ret;
}

void act_start_webserver::deinit()
{
	m_webserver.stop();
}

}; // namespace application
}; // namespace falco

#endif
