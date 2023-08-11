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
#include "grpc_server.h"
#endif

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::start_grpc_server(falco::app::state& s)
{
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
	// gRPC server
	if(s.config->m_grpc_enabled)
	{
		if (s.options.dry_run)
		{
			falco_logger::log(LOG_DEBUG, "Skipping starting gRPC server in dry-run\n");
			return run_result::ok();
		}

		falco_logger::log(LOG_INFO, "gRPC server threadiness equals to " + std::to_string(s.config->m_grpc_threadiness) + "\n");
		// TODO(fntlnz,leodido): when we want to spawn multiple threads we need to have a queue per thread, or implement
		// different queuing mechanisms, round robin, fanout? What we want to achieve?
		s.grpc_server.init(
			s.config->m_grpc_bind_address,
			s.config->m_grpc_threadiness,
			s.config->m_grpc_private_key,
			s.config->m_grpc_cert_chain,
			s.config->m_grpc_root_certs,
			s.config->m_log_level
			);
		s.grpc_server_thread = std::thread([&s] {
			s.grpc_server.run();
		});
	}
#endif
	return run_result::ok();
}

falco::app::run_result falco::app::actions::stop_grpc_server(falco::app::state& s)
{
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
	if(s.config->m_grpc_enabled)
	{
		if (s.options.dry_run)
		{
			falco_logger::log(LOG_DEBUG, "Skipping stopping gRPC server in dry-run\n");
			return run_result::ok();
		}

		if(s.grpc_server_thread.joinable())
		{
			s.grpc_server.shutdown();
			s.grpc_server_thread.join();
		}
	}
#endif
	return run_result::ok();
}

