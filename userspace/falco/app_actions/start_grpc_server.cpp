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

#include "grpc_server.h"

using namespace falco::app;

application::run_result application::start_grpc_server()
{
	// gRPC server
	if(m_state->config->m_grpc_enabled)
	{
		falco_logger::log(LOG_INFO, "gRPC server threadiness equals to " + std::to_string(m_state->config->m_grpc_threadiness) + "\n");
		// TODO(fntlnz,leodido): when we want to spawn multiple threads we need to have a queue per thread, or implement
		// different queuing mechanisms, round robin, fanout? What we want to achieve?
		m_state->grpc_server.init(
			m_state->config->m_grpc_bind_address,
			m_state->config->m_grpc_threadiness,
			m_state->config->m_grpc_private_key,
			m_state->config->m_grpc_cert_chain,
			m_state->config->m_grpc_root_certs,
			m_state->config->m_log_level
			);
		m_state->grpc_server_thread = std::thread([this] {
			m_state->grpc_server.run();
		});
	}
	return run_result::ok();
}

bool application::stop_grpc_server(std::string &errstr)
{
	if(m_state->grpc_server_thread.joinable())
	{
		m_state->grpc_server.shutdown();
		m_state->grpc_server_thread.join();
	}

	return true;
}

#endif
