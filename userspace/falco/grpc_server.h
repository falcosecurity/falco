/*
Copyright (C) 2016-2019 The Falco Authors

This file is part of falco.

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

#include <thread>
#include <string>

#include "falco_output.grpc.pb.h"
#include "falco_output.pb.h"
#include "grpc_context.h"

class grpc_server_impl
{
public:
	grpc_server_impl() = default;
	~grpc_server_impl() = default;

protected:
	bool is_running();

	void subscribe_handler(const stream_context& ctx, falco_output_request req, falco_output_response res);
};

class grpc_server : public grpc_server_impl
{
public:
	grpc_server(std::string server_addr, int threadiness):
		m_server_addr(server_addr),
		m_threadiness(threadiness)
	{
	}
	virtual ~grpc_server() = default;

	void thread_process(int thread_index);
	void run();
	void subscribe_handler(const stream_context& ctx, falco_output_request req, falco_output_response res);

private:
	// falco_output_service::AsyncService falco_output_svc;
	std::unique_ptr<grpc::Server> m_server;
	std::string m_server_addr;
	int m_threadiness = 0;
	std::unique_ptr<grpc::ServerCompletionQueue> m_completion_queue;
	std::vector<std::thread> m_threads;
};

void start_grpc_server(std::string server_address, int threadiness);
