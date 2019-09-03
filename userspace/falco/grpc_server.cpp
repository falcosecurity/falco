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

#include <iostream>

#ifdef GRPC_INCLUDE_IS_GRPCPP
#include <grpcpp/grpcpp.h>
#else
#include <grpc++/grpc++.h>
#endif

#include "grpc_server.h"
#include "grpc_context.h"

template<>
void request_stream_context<falco_output_request, falco_output_response>::start(falco_grpc_server* srv)
{
	m_state = request_context_base::REQUEST;
	m_srv_ctx.reset(new grpc::ServerContext);
	auto srvctx = m_srv_ctx.get();
	m_res_writer.reset(new grpc::ServerAsyncWriter<falco_output_response>(srvctx));
	m_stream_ctx.reset();
	m_req.Clear();

	auto cq = srv->m_completion_queue.get();
	(srv->m_svc.*m_request_func)(srvctx, &m_req, m_res_writer.get(), cq, cq, this);
}

template<>
void request_stream_context<falco_output_request, falco_output_response>::process(falco_grpc_server* srv)
{
}

template<>
void request_stream_context<falco_output_request, falco_output_response>::end(falco_grpc_server* srv, bool isError)
{
}

bool falco_grpc_server_impl::is_running()
{
	// TODO: this must act as a switch to shut down the server
	return true;
}

void falco_grpc_server_impl::subscribe(const stream_context& ctx, const falco_output_request& req, falco_output_response& res)
{
	if(ctx.m_status == stream_context::SUCCESS || ctx.m_status == stream_context::ERROR)
	{
		// todo > logic

		ctx.m_stream = nullptr;
	}
	else
	{
		// Start (or continue) streaming
		// ctx.m_status == stream_context::STREAMING
	}

	// todo > print/store statistics
}

void falco_grpc_server::thread_process(int thread_index)
{
	// TODO: is this right? That's what we want?
	// Tell pthread to not handle termination signals in the current thread
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGINT);
	pthread_sigmask(SIG_BLOCK, &set, nullptr);

	void* tag = nullptr;
	bool event_read_success = false;
	while(m_completion_queue->Next(&tag, &event_read_success))
	{
		if(tag == nullptr)
		{
			// TODO: empty tag returned, log, what to do?
			continue;
		}
	}
}

//
// Create array of contexts and start processing streaming RPC request.
//
#define PROCESS_STREAM(REQ, RESP, RPC, IMPL, CONTEXT_COUNT)                             \
	std::vector<request_stream_context<REQ, RESP>> RPC##_contexts(CONTEXT_COUNT);   \
	for(request_stream_context<REQ, RESP> & ctx : RPC##_contexts)                   \
	{                                                                               \
		ctx.m_process_func = &falco_grpc_server::IMPL;                          \
		ctx.m_request_func = &falco_output_service::AsyncService::Request##RPC; \
		ctx.start(this);                                                        \
	}

void falco_grpc_server::run()
{
	grpc::ServerBuilder builder;
	// Listen on the given address without any authentication mechanism.
	builder.AddListeningPort(m_server_addr, grpc::InsecureServerCredentials());
	// builder.RegisterService(&falco_output_svc); // TODO: enable this when we do the impl

	m_completion_queue = builder.AddCompletionQueue();
	m_server = builder.BuildAndStart();
	std::cout << "Server listening on " << m_server_addr << std::endl;

	int context_count = m_threadiness * 10;
	PROCESS_STREAM(falco_output_request, falco_output_response, subscribe, subscribe, context_count)

	m_threads.resize(m_threadiness);
	int thread_idx = 0;
	for(std::thread& thread : m_threads)
	{
		thread = std::thread(&falco_grpc_server::thread_process, this, thread_idx++);
	}

	while(is_running())
	{
	}
}

void start_grpc_server(std::string server_address, int threadiness)
{
	falco_grpc_server srv(server_address, threadiness);
	srv.run();
}