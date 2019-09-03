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

class falco_grpc_server_impl
{
public:
	falco_grpc_server_impl() = default;
	~falco_grpc_server_impl() = default;

protected:
	bool is_running();

	void subscribe(const stream_context& ctx, const falco_output_request& req, falco_output_response& res);
};

class falco_grpc_server : public falco_grpc_server_impl
{
public:
	falco_grpc_server(std::string server_addr, int threadiness):
		m_server_addr(server_addr),
		m_threadiness(threadiness)
	{
	}
	virtual ~falco_grpc_server() = default;

	void thread_process(int thread_index);
	void run();

	falco_output_service::AsyncService m_svc;
	std::unique_ptr<grpc::ServerCompletionQueue> m_completion_queue;

private:
	std::unique_ptr<grpc::Server> m_server;
	std::string m_server_addr;
	int m_threadiness = 0;
	std::vector<std::thread> m_threads;

};

void start_grpc_server(std::string server_address, int threadiness);


