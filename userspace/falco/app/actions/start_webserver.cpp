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

#if !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__)
#include "webserver.h"
#endif

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::start_webserver(falco::app::state& s)
{
#if !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__)
	if(!s.is_capture_mode() && s.config->m_webserver_enabled)
	{
		if (s.options.dry_run)
		{
			falco_logger::log(LOG_DEBUG, "Skipping starting webserver in dry-run\n");
			return run_result::ok();
		}
	
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
#endif
	return run_result::ok();
}

falco::app::run_result falco::app::actions::stop_webserver(falco::app::state& s)
{
#if !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__)
	if(!s.is_capture_mode() && s.config->m_webserver_enabled)
	{
		if (s.options.dry_run)
		{
			falco_logger::log(LOG_DEBUG, "Skipping stopping webserver in dry-run\n");
			return run_result::ok();
		}

		s.webserver.stop();
	}
#endif
	return run_result::ok();
}

