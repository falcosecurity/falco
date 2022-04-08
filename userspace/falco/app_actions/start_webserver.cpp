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

#ifndef MINIMAL_BUILD

#include "webserver.h"

using namespace falco::app;

application::run_result application::start_webserver()
{
	run_result ret;

	if(m_options.trace_filename.empty() && m_state->config->m_webserver_enabled && m_state->enabled_sources.find(application::s_k8s_audit_source) != m_state->enabled_sources.end())
	{
		std::string ssl_option = (m_state->config->m_webserver_ssl_enabled ? " (SSL)" : "");
		falco_logger::log(LOG_INFO, "Starting internal webserver, listening on port " + to_string(m_state->config->m_webserver_listen_port) + ssl_option + "\n");
		m_state->webserver.init(m_state->config, m_state->engine, m_state->outputs, m_state->k8s_audit_source_idx);
		m_state->webserver.start();
	}

	return ret;
}

bool application::stop_webserver(std::string &errstr)
{
	m_state->webserver.stop();

	return true;
}

#endif
