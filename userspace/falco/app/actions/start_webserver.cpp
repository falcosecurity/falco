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

#include "actions.h"

#ifndef MINIMAL_BUILD

#include "webserver.h"

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::start_webserver(falco::app::state& s)
{
	if(!s.is_capture_mode() && s.config->m_webserver_enabled)
	{
		std::string ssl_option = (s.config->m_webserver_ssl_enabled ? " (SSL)" : "");
		falco_logger::log(LOG_INFO, "Starting health webserver with threadiness "
			+ std::to_string(s.config->m_webserver_threadiness)
			+ ", listening on port "
			+ std::to_string(s.config->m_webserver_listen_port)
			+ ssl_option + "\n");

		s.webserver.start(
			s.offline_inspector,
			s.config->m_webserver_threadiness,
			s.config->m_webserver_listen_port, 
			s.config->m_webserver_k8s_healthz_endpoint,
			s.config->m_webserver_ssl_certificate, 
			s.config->m_webserver_ssl_enabled);
	}
	return run_result::ok();
}

bool falco::app::actions::stop_webserver(falco::app::state& s, std::string &errstr)
{
	if(!s.is_capture_mode())
	{
		s.webserver.stop();
	}
	return true;
}

#endif
