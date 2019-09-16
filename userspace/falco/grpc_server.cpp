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

#ifdef GRPC_INCLUDE_IS_GRPCPP
#include <grpcpp/grpcpp.h>
#else
#include <grpc++/grpc++.h>
#endif
#include <signal.h> // pthread_sigmask
#include <unistd.h> // sleep, _exit

#include "logger.h"
#include "grpc_server.h"
#include "grpc_context.h"

template<>
void request_stream_context<request, response>::start(falco_grpc_server* srv)
{
	m_state = request_context_base::REQUEST;
	m_srv_ctx.reset(new grpc::ServerContext);
	auto srvctx = m_srv_ctx.get();
	m_res_writer.reset(new grpc::ServerAsyncWriter<response>(srvctx));
	m_stream_ctx.reset();
	m_req.Clear();

	auto cq = srv->m_completion_queue.get();
	(srv->m_svc.*m_request_func)(srvctx, &m_req, m_res_writer.get(), cq, cq, this);
}

template<>
void request_stream_context<request, response>::process(falco_grpc_server* srv)
{
	// When it is the 1st process call
	if(m_state == request_context_base::REQUEST)
	{
		m_state = request_context_base::WRITE;
		m_stream_ctx.reset(new stream_context(m_srv_ctx.get()));
	}

	// Processing
	response res;
	(srv->*m_process_func)(*m_stream_ctx, m_req, res);

	// When there still are more responses to stream
	if(m_stream_ctx->m_has_more)
	{
		m_res_writer->Write(res, this);
	}
	// No more responses to stream
	else
	{
		// Communicate to the gRPC runtime that we have finished.
		// The memory address of `this` instance uniquely identifies the event.
		m_state = request_context_base::FINISH;
		m_res_writer->Finish(grpc::Status::OK, this);
	}
}

template<>
void request_stream_context<request, response>::end(falco_grpc_server* srv, bool isError)
{
	if(m_stream_ctx)
	{
		m_stream_ctx->m_status = stream_context::SUCCESS;
		if(isError)
		{
			m_stream_ctx->m_status = stream_context::ERROR;
			// todo > log error
		}

		// Complete the processing
		response res;
		(srv->*m_process_func)(*m_stream_ctx, m_req, res); // subscribe()
	}
	else
	{
		// Handle the edge case when `m_request_func` event failed
		// which means `m_stream_ctx` was not set
		// todo > log error
	}

	start(srv);
}

void falco_grpc_server::thread_process(int thread_index)
{
	// Tell pthread to not handle termination signals in the current thread
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	// sigaddset(&set, SIGHUP); // todo > SIGHUP should restart Falco, what to do?
	sigaddset(&set, SIGINT);
	pthread_sigmask(SIG_BLOCK, &set, nullptr);

	void* tag = nullptr;
	bool event_read_success = false;
	while(m_completion_queue->Next(&tag, &event_read_success))
	{
		if(tag == nullptr)
		{
			// TODO: empty tag returned, log "completion queue with empty tag"
			continue;
		}

		// Obtain the context for a given tag
		request_context_base* ctx = static_cast<request_context_base*>(tag);

		// When event has not been read successfully
		if(!event_read_success)
		{
			if(ctx->m_state != request_context_base::REQUEST)
			{
				// todo > log "server completion queue failed to read event for tag `tag`"
				// End the context with error
				ctx->end(this, true);
			}
			continue;
		}

		// Process the event
		switch(ctx->m_state)
		{
		case request_context_base::REQUEST:
			// Completion of m_request_func
		case request_context_base::WRITE:
			// Completion of ServerAsyncWriter::Write()
			ctx->process(this);
			break;
		case request_context_base::FINISH:
			// Completion of ServerAsyncWriter::Finish()
			ctx->end(this, false);

		default:
			// todo > log "unkown completion queue event"
			// todo > abort?
			break;
		}
	}

	// todo > log "thread `thread_index` complete"
}

//
// Create array of contexts and start processing streaming RPC request.
//
#define PROCESS_STREAM(REQ, RESP, RPC, IMPL, CONTEXT_COUNT)                           \
	std::vector<request_stream_context<REQ, RESP>> RPC##_contexts(CONTEXT_COUNT); \
	for(request_stream_context<REQ, RESP> & ctx : RPC##_contexts)                 \
	{                                                                             \
		ctx.m_process_func = &falco_grpc_server::IMPL;                        \
		ctx.m_request_func = &service::AsyncService::Request##RPC;            \
		ctx.start(this);                                                      \
	}

// todo(fntlnz, leodido) > cleanup this part (paths from config, read, includes)
#include <sstream>
#include <fstream>
#include <iostream>

void read(const std::string& filename, std::string& data)
{
	std::ifstream file(filename.c_str(), std::ios::in);

	if(file.is_open())
	{
		std::stringstream ss;
		ss << file.rdbuf();

		file.close();

		data = ss.str();
	}

	return;
}

extern "C" void handle_signal(int signum)
{
	// todo > print "Got signal << sigenum << : exiting...");
	// exit(1);
}

void falco_grpc_server::run()
{
	// Handle SIGHUP and SIGINT in the main process.
	// Not in the spawned threads.
	// sigset_t set;
	// sigemptyset(&set);
	// sigaddset(&set, SIGTERM);
	// // sigaddset(&set, SIGHUP); // todo > SIGHUP should restart Falco, what to do?
	// sigaddset(&set, SIGINT);
	// pthread_sigmask(SIG_UNBLOCK, &set, nullptr);

	// struct sigaction action;
	// action.sa_handler = handle_signal;
	// sigaction(SIGHUP, &action, nullptr);
	// sigaction(SIGINT, &action, nullptr);

	string private_key;
	string cert_chain;
	string root_certs;

	read("/tmp/server.crt", cert_chain);
	read("/tmp/server.key", private_key);
	read("/tmp/ca.crt", root_certs);

	grpc::SslServerCredentialsOptions::PemKeyCertPair cert_pair{private_key, cert_chain};

	grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
	ssl_opts.pem_root_certs = root_certs;
	ssl_opts.pem_key_cert_pairs.push_back(cert_pair);

	// Setup server
	grpc::ServerBuilder builder;
	// Listen on the given address without any authentication mechanism.
	builder.AddListeningPort(m_server_addr, grpc::SslServerCredentials(ssl_opts));
	builder.RegisterService(&m_svc);

	// builder.SetMaxSendMessageSize(GRPC_MAX_MESSAGE_SIZE);     // testing max message size?
	// builder.SetMaxReceiveMessageSize(GRPC_MAX_MESSAGE_SIZE);  // testing max message size?

	m_completion_queue = builder.AddCompletionQueue();
	m_server = builder.BuildAndStart();
	falco_logger::log(LOG_INFO, "Starting gRPC webserver at " + m_server_addr + "\n");

	// Create context for server threads
	// The number of contexts is multiple of the number of threads
	// This defines the number of simultaneous completion queue requests of the same type (service::AsyncService::Request##RPC)
	// For this approach to be sufficient falco_grpc_server::IMPL have to be fast
	int context_count = m_threadiness * 10;
	PROCESS_STREAM(request, response, subscribe, subscribe, context_count)

	m_threads.resize(m_threadiness);
	int thread_idx = 0;
	for(std::thread& thread : m_threads)
	{
		thread = std::thread(&falco_grpc_server::thread_process, this, thread_idx++);
	}

	while(is_running())
	{
		sleep(1); // todo > do we want to sleep here?
	}

	stop();
}

void falco_grpc_server::stop()
{
	m_server->Shutdown();
	m_completion_queue->Shutdown();

	// todo > log "waiting for the server threads to complete"

	for(std::thread& t : m_threads)
	{
		t.join();
	}
	m_threads.clear();

	// todo > log "all server threads complete"

	// Ignore remaining events
	void* ignore_tag = nullptr;
	bool ignore_ok = false;
	while(m_completion_queue->Next(&ignore_tag, &ignore_ok))
	{
	}
}

bool start_grpc_server(std::string server_address, int threadiness)
{
	falco_grpc_server srv(server_address, threadiness);
	srv.run();
	return true;
}
