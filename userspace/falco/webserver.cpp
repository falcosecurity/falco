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

	// run server in a separate thread
	if(!m_server->is_valid()) {
		m_server = nullptr;
		throw falco_exception("invalid webserver configuration");
	}

	m_failed.store(false, std::memory_order_release);
	m_server_thread = std::thread([this, webserver_config] {
		try {
			this->m_server->listen(webserver_config.m_listen_address,
			                       webserver_config.m_listen_port);
		} catch(std::exception &e) {
			falco_logger::log(falco_logger::level::ERR,
			                  "falco_webserver: " + std::string(e.what()) + "\n");
		}
		this->m_failed.store(true, std::memory_order_release);
	});

	// wait for the server to actually start up
	// note: is_running() is atomic
	while(!m_server->is_running() && !m_failed.load(std::memory_order_acquire)) {
		std::this_thread::yield();
	}
	m_running = true;
	if(m_failed.load(std::memory_order_acquire)) {
		stop();
		throw falco_exception("an error occurred while starting webserver");
	}
}

void falco_webserver::stop() {
	if(m_running) {
		if(m_server != nullptr) {
			m_server->stop();
		}
		if(m_server_thread.joinable()) {
			m_server_thread.join();
		}
		m_server = nullptr;
		m_running = false;
	}
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
