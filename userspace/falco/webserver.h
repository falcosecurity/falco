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
#pragma once

#define CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_ZLIB_SUPPORT
#include <httplib.h>
#include <thread>
#include "configuration.h"

class falco_webserver
{
public:
	virtual ~falco_webserver();
	virtual void start(
		uint32_t listen_port,
		std::string& healthz_endpoint,
		std::string &ssl_certificate,
		bool ssl_enabled);
	virtual void stop();

private:
	bool m_running = false;
	httplib::Server* m_server = NULL;
	std::thread m_server_thread;
};
