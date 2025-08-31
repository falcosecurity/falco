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

#include "webserver.h"
#include "falco_utils.h"
#include "falco_metrics.h"
#include "app/state.h"
#include "versions_info.h"
#include <atomic>
#include <signal.h>

falco_webserver::~falco_webserver() {
	stop();
}

void falco_webserver::start(const falco::app::state &state,
                            const falco_configuration::webserver_config &webserver_config) {
	if(m_running) {
		throw falco_exception("attempted restarting webserver without stopping it first");
	}

	// allocate and configure server
	if(webserver_config.m_ssl_enabled) {
		m_server = std::make_unique<httplib::SSLServer>(webserver_config.m_ssl_certificate.c_str(),
		                                                webserver_config.m_ssl_certificate.c_str());
	} else {
		m_server = std::make_unique<httplib::Server>();
	}

	// configure server
	m_server->new_task_queue = [webserver_config] {
		return new httplib::ThreadPool(webserver_config.m_threadiness);
	};

	// setup healthz endpoint
	m_server->Get(webserver_config.m_k8s_healthz_endpoint,
	              [](const httplib::Request &, httplib::Response &res) {
		              res.set_content("{\"status\": \"ok\"}", "application/json");
	              });

	// setup versions endpoint
	const auto versions_json_str = falco::versions_info(state.offline_inspector).as_json().dump();
	m_server->Get("/versions",
	              [versions_json_str](const httplib::Request &, httplib::Response &res) {
		              res.set_content(versions_json_str, "application/json");
	              });

	if(!m_server->is_valid()) {
		m_server = nullptr;
		throw falco_exception("invalid webserver configuration");
	}

	m_failed.store(false, std::memory_order_release);

	// fork the server
	m_pid = fork();

	if(m_pid == 0) {
		falco_logger::log(falco_logger::level::INFO, "Webserver: forked\n");
		int res = setgid(webserver_config.m_uid);
		if(res != NOERROR) {
			throw falco_exception("Webserver: an error occurred while setting group id: " +
			                      std::to_string(errno));
		}
		res = setuid(webserver_config.m_gid);
		if(res != NOERROR) {
			throw falco_exception("Webserver: an error occurred while setting user id: " +
			                      std::to_string(errno));
		}
		falco_logger::log(falco_logger::level::INFO,
		                  "Webserver: fork running as " + std::to_string(webserver_config.m_uid) +
		                          ":" + std::to_string(webserver_config.m_gid) + "\n");
		try {
			this->m_server->listen(webserver_config.m_listen_address,
			                       webserver_config.m_listen_port);
		} catch(std::exception &e) {
			falco_logger::log(falco_logger::level::ERR,
			                  "Webserver: " + std::string(e.what()) + "\n");
			m_failed.store(true, std::memory_order_release);
		}
	} else if(m_pid < 0) {
		throw falco_exception("Webserver: an error occurred while forking webserver");
	}
}

void falco_webserver::stop() {
	if(m_pid > 0) {
		falco_logger::log(falco_logger::level::INFO, "Webserver: stopping server\n");
		if(m_server != nullptr) {
			m_server->stop();
		}
		falco_logger::log(falco_logger::level::INFO, "Webserver: killing fork\n");
		int res = kill(m_pid, SIGTERM);
		if(res != 0) {
			throw falco_exception("Webserver: an error occurred while killing fork: " +
			                      std::to_string(errno));
		}
		m_pid = 0;
		falco_logger::log(falco_logger::level::INFO, "Webserver: stopping fork done\n");
	}

	m_server = nullptr;
	m_running = false;
}

void falco_webserver::enable_prometheus_metrics(const falco::app::state &state) {
	if(state.config->m_metrics_enabled &&
	   state.config->m_webserver_config.m_prometheus_metrics_enabled) {
		m_server->Get("/metrics", [&state](const httplib::Request &, httplib::Response &res) {
			res.set_content(falco_metrics::to_text_prometheus(state),
			                falco_metrics::content_type_prometheus);
		});
	}
}
