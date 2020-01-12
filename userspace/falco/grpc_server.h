/*
Copyright (C) 2019 The Falco Authors

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

#include "grpc_server_impl.h"

namespace falco
{
namespace grpc
{
class server : public server_impl
{
public:
	server()
	{
	}
	server(std::string server_addr, int threadiness, std::string private_key, std::string cert_chain, std::string root_certs):
		m_server_addr(server_addr),
		m_threadiness(threadiness),
		m_private_key(private_key),
		m_cert_chain(cert_chain),
		m_root_certs(root_certs)
	{
	}
	virtual ~server() = default;

	void init(std::string server_addr, int threadiness, std::string private_key, std::string cert_chain, std::string root_certs);
	void thread_process(int thread_index);
	void run();
	void stop();

	output::service::AsyncService m_svc;
	std::unique_ptr<::grpc::ServerCompletionQueue> m_completion_queue;

private:
	std::string m_server_addr;
	int m_threadiness;
	std::string m_private_key;
	std::string m_cert_chain;
	std::string m_root_certs;

	std::unique_ptr<::grpc::Server> m_server;
	std::vector<std::thread> m_threads;
};

class request_context_base
{
public:
	request_context_base() = default;
	~request_context_base() = default;

	std::unique_ptr<::grpc::ServerContext> m_srv_ctx;
	enum : char
	{
		UNKNOWN = 0,
		REQUEST,
		WRITE,
		FINISH
	} m_state = UNKNOWN;
	virtual void start(server* srv) = 0;
	virtual void process(server* srv) = 0;
	virtual void end(server* srv, bool isError) = 0;
};

//
// Template class to handle streaming responses
//
template<class Request, class Response>
class request_stream_context : public request_context_base
{
public:
	request_stream_context():
		m_process_func(nullptr),
		m_request_func(nullptr){};
	~request_stream_context() = default;

	// Pointer to function that does actual processing
	void (server::*m_process_func)(const stream_context&, const Request&, Response&);

	// Pointer to function that requests the system to start processing given requests
	void (output::service::AsyncService::*m_request_func)(::grpc::ServerContext*, Request*, ::grpc::ServerAsyncWriter<Response>*, ::grpc::CompletionQueue*, ::grpc::ServerCompletionQueue*, void*);

	void start(server* srv);
	void process(server* srv);
	void end(server* srv, bool isError);

private:
	std::unique_ptr<::grpc::ServerAsyncWriter<Response>> m_res_writer;
	std::unique_ptr<stream_context> m_stream_ctx;
	Request m_req;
};
} // namespace grpc
} // namespace falco
