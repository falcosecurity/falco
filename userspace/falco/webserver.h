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
#pragma once

#include "configuration.h"

#include <libsinsp/sinsp.h>

#include <httplib.h>

#include <memory>
#include <thread>

class falco_webserver
{
public:
	falco_webserver() = default;
	virtual ~falco_webserver();
	falco_webserver(falco_webserver&&) = default;
	falco_webserver& operator = (falco_webserver&&) = default;
	falco_webserver(const falco_webserver&) = delete;
	falco_webserver& operator = (const falco_webserver&) = delete;
	virtual void start(
		const std::shared_ptr<sinsp>& inspector,
		uint32_t threadiness,
		uint32_t listen_port,
		std::string& list_address,
		std::string& healthz_endpoint,
		std::string &ssl_certificate,
		bool ssl_enabled);
	virtual void stop();

private:
	bool m_running = false;
	std::unique_ptr<httplib::Server> m_server = nullptr;
	std::thread m_server_thread;
};
