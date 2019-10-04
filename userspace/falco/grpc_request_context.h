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

#include "grpc_server.h"

namespace falco
{
namespace grpc
{

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

// The responsibility of `request_stream_context` template class
// is to handle streaming responses.
template<class Service, class Request, class Response>
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
	void (Service::AsyncService::*m_request_func)(::grpc::ServerContext*, Request*, ::grpc::ServerAsyncWriter<Response>*, ::grpc::CompletionQueue*, ::grpc::ServerCompletionQueue*, void*);

	void start(server* srv);
	void process(server* srv);
	void end(server* srv, bool isError);

private:
	std::unique_ptr<::grpc::ServerAsyncWriter<Response>> m_res_writer;
	std::unique_ptr<stream_context> m_stream_ctx;
	Request m_req;
};

// The responsibility of `request_context` template class
// is to handle unary responses.
template<class Service, class Request, class Response>
class request_context : public request_context_base
{
public:
	request_context():
		m_process_func(nullptr),
		m_request_func(nullptr){};
	~request_context() = default;

	// Pointer to function that does actual processing
	void (server::*m_process_func)(const context&, const Request&, Response&);

	// Pointer to function that requests the system to start processing given requests
	void (Service::AsyncService::*m_request_func)(::grpc::ServerContext*, Request*, ::grpc::ServerAsyncResponseWriter<Response>*, ::grpc::CompletionQueue*, ::grpc::ServerCompletionQueue*, void*);

	void start(server* srv);
	void process(server* srv);
	void end(server* srv, bool isError);

private:
	std::unique_ptr<::grpc::ServerAsyncWriter<Response>> m_res_writer;
	Request m_req;
};
} // namespace grpc
} // namespace falco