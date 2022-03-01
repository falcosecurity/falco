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

#include "start_grpc_server.h"

#ifndef MINIMAL_BUILD

namespace falco {
namespace app {

act_start_grpc_server::act_start_grpc_server(application &app)
	: init_action(app), m_name("start grpc server"),
	  m_prerequsites({"init outputs"})
{
}

act_start_grpc_server::~act_start_grpc_server()
{
}

const std::string &act_start_grpc_server::name()
{
	return m_name;
}

const std::list<std::string> &act_start_grpc_server::prerequsites()
{
	return m_prerequsites;
}

runnable_action::run_result act_start_grpc_server::run()
{
	run_result ret = {true, "", true};

	// gRPC server
	if(state().config->m_grpc_enabled)
	{
		falco_logger::log(LOG_INFO, "gRPC server threadiness equals to " + to_string(state().config->m_grpc_threadiness) + "\n");
		// TODO(fntlnz,leodido): when we want to spawn multiple threads we need to have a queue per thread, or implement
		// different queuing mechanisms, round robin, fanout? What we want to achieve?
		m_grpc_server.init(
			state().config->m_grpc_bind_address,
			state().config->m_grpc_threadiness,
			state().config->m_grpc_private_key,
			state().config->m_grpc_cert_chain,
			state().config->m_grpc_root_certs,
			state().config->m_log_level
			);
		m_grpc_server_thread = std::thread([this] {
			m_grpc_server.run();
		});
	}
	return ret;
}

void act_start_grpc_server::deinit()
{
	if(m_grpc_server_thread.joinable())
	{
		m_grpc_server.shutdown();
		m_grpc_server_thread.join();
	}
}

}; // namespace application
}; // namespace falco

#endif
