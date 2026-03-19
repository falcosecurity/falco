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

#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
#include "webserver.h"
#endif

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::start_webserver(falco::app::state& state) {
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
	if(state.is_capture_mode() || !state.config->m_webserver_enabled) {
		return run_result::ok();
	}

	if(state.options.dry_run) {
		falco_logger::log(falco_logger::level::DEBUG, "Skipping starting webserver in dry-run\n");
		return run_result::ok();
	}

	falco_configuration::webserver_config webserver_config = state.config->m_webserver_config;
	std::string ssl_option = (webserver_config.m_ssl_enabled ? " (SSL)" : "");
	falco_logger::log(falco_logger::level::INFO,
	                  "Starting health webserver with threadiness " +
	                          std::to_string(webserver_config.m_threadiness) + ", listening on " +
	                          webserver_config.m_listen_address + ":" +
	                          std::to_string(webserver_config.m_listen_port) + ssl_option + "\n");

	state.webserver.start(state, webserver_config);
	state.on_inspectors_opened = [&state]() { state.webserver.enable_prometheus_metrics(state); };
#endif
	return run_result::ok();
}

falco::app::run_result falco::app::actions::stop_webserver(falco::app::state& state) {
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
	if(state.is_capture_mode() || !state.config->m_webserver_enabled) {
		return run_result::ok();
	}

	if(state.options.dry_run) {
		falco_logger::log(falco_logger::level::DEBUG, "Skipping stopping webserver in dry-run\n");
		return run_result::ok();
	}

	state.webserver.stop();
#endif
	return run_result::ok();
}
