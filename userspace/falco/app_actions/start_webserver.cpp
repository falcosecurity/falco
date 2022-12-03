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
	if(!is_capture_mode() && m_state->config->m_webserver_enabled)
	{
		std::string ssl_option = (m_state->config->m_webserver_ssl_enabled ? " (SSL)" : "");
		falco_logger::log(LOG_INFO, "Starting health webserver with threadiness "
			+ std::to_string(m_state->config->m_webserver_threadiness)
			+ ", listening on port "
			+ std::to_string(m_state->config->m_webserver_listen_port)
			+ ssl_option + "\n");

		m_state->webserver.start(
			m_state->config->m_webserver_threadiness,
			m_state->config->m_webserver_listen_port, 
			m_state->config->m_webserver_k8s_healthz_endpoint,
			m_state->config->m_webserver_ssl_certificate, 
			m_state->config->m_webserver_ssl_enabled);
	}
	return run_result::ok();
}

bool application::stop_webserver(std::string &errstr)
{
	if(!is_capture_mode())
	{
		m_state->webserver.stop();
	}
	return true;
}

#endif
