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

#include <unistd.h>

#ifdef GRPC_INCLUDE_IS_GRPCPP
#include <grpcpp/grpcpp.h>
#else
#include <grpc++/grpc++.h>
#endif

#include "grpc_server.h"
#include "grpc_request_context.h"
#include "utils.h"
#include "banned.h"

#define REGISTER_STREAM(req, res, svc, rpc, impl, num)                          \
	std::vector<request_stream_context<svc, req, res>> rpc##_contexts(num); \
	for(request_stream_context<svc, req, res> & c : rpc##_contexts)         \
	{                                                                       \
		c.m_process_func = &server::impl;                               \
		c.m_request_func = &svc::AsyncService::Request##rpc;            \
		c.start(this);                                                  \
	}

#define REGISTER_UNARY(req, res, svc, rpc, impl, num)                    \
	std::vector<request_context<svc, req, res>> rpc##_contexts(num); \
	for(request_context<svc, req, res> & c : rpc##_contexts)         \
	{                                                                \
		c.m_process_func = &server::impl;                        \
		c.m_request_func = &svc::AsyncService::Request##rpc;     \
		c.start(this);                                           \
	}

void falco::grpc::server::thread_process(int thread_index)
{
	void* tag = nullptr;
	bool event_read_success = false;
	while(m_completion_queue->Next(&tag, &event_read_success))
	{
		if(tag == nullptr)
		{
			gpr_log(
				GPR_ERROR,
				"server::%s -> server completion queue error: tag=(empty)",
				__func__);
			continue;
		}

		// Obtain the context for a given tag
		request_context_base* ctx = static_cast<request_context_base*>(tag);

		gpr_log(
			GPR_DEBUG,
			"server::%s -> next event: tag=%p, read success=%s, state=%s",
			__func__,
			tag,
			event_read_success ? "true" : "false",
			ctx->m_state == request_context_base::REQUEST ? "request" : ctx->m_state == request_context_base::WRITE ? "write" : ctx->m_state == request_context_base::FINISH ? "finish" : "unknown");

		// When event has not been read successfully
		if(!event_read_success)
		{
			if(ctx->m_state != request_context_base::REQUEST)
			{
				gpr_log(
					GPR_ERROR,
					"server::%s -> server completion queue failing to read: tag=%p",
					__func__,
					tag);

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
			// Completion of Write()
			ctx->process(this);
			break;
		case request_context_base::FINISH:
			// Completion of Finish()
			ctx->end(this, false);
			break;
		default:
			gpr_log(
				GPR_ERROR,
				"server::%s -> unkown completion queue event: tag=%p, state=%s",
				__func__,
				tag,
				ctx->m_state == request_context_base::REQUEST ? "request" : ctx->m_state == request_context_base::WRITE ? "write" : ctx->m_state == request_context_base::FINISH ? "finish" : "unknown");
			break;
		}

		gpr_log(
			GPR_DEBUG,
			"server::%s -> thread completed: tag=%p, index=%d",
			__func__,
			tag,
			thread_index);
	}
}

void falco::grpc::server::init(std::string server_addr, std::string private_key, std::string cert_chain, std::string root_certs, int threadiness, std::string log_level)
{
	m_server_addr = server_addr;
	m_threadiness = threadiness;
	m_private_key = private_key;
	m_cert_chain = cert_chain;
	m_root_certs = root_certs;

	if(log_level == "info")
	{
		gpr_set_log_verbosity(GPR_LOG_SEVERITY_INFO);
	}
	else if(log_level == "debug")
	{
		gpr_set_log_verbosity(GPR_LOG_SEVERITY_DEBUG);
	}
	else if(log_level == "error")
	{
		gpr_set_log_verbosity(GPR_LOG_SEVERITY_ERROR);
	}
	else
	{
		// defaulting to INFO severity for severities unknown to gRPC logging mechanism
		gpr_set_log_verbosity(GPR_LOG_SEVERITY_INFO);
	}

	// gpr_set_log_function(test_callback);
	gpr_log_verbosity_init();
}

// static void test_callback(gpr_log_func_args* args){};

void falco::grpc::server::run()
{
	std::string private_key;
	std::string cert_chain;
	std::string root_certs;

	falco::utils::read(m_cert_chain, cert_chain);
	falco::utils::read(m_private_key, private_key);
	falco::utils::read(m_root_certs, root_certs);

	::grpc::SslServerCredentialsOptions::PemKeyCertPair cert_pair{private_key, cert_chain};

	::grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
	ssl_opts.pem_root_certs = root_certs;
	ssl_opts.pem_key_cert_pairs.push_back(cert_pair);

	::grpc::ServerBuilder builder;
	builder.AddListeningPort(m_server_addr, ::grpc::SslServerCredentials(ssl_opts));
	builder.RegisterService(&m_output_svc);
	builder.RegisterService(&m_version_svc);

	m_completion_queue = builder.AddCompletionQueue();
	m_server = builder.BuildAndStart();
	gpr_log(GPR_INFO, "gRPC server starting: address=%s", m_server_addr.c_str());

	// The number of contexts is multiple of the number of threads
	// This defines the number of simultaneous completion queue requests of the same type (service::AsyncService::Request##RPC)
	// For this approach to be sufficient server::IMPL have to be fast
	int context_num = m_threadiness * 10;
	// todo(leodido) > take a look at thread_stress_test.cc into grpc repository

	REGISTER_UNARY(version::request, version::response, version::service, version, version, context_num)
	REGISTER_STREAM(output::request, output::response, output::service, subscribe, subscribe, context_num)

	m_threads.resize(m_threadiness);
	int thread_idx = 0;
	for(std::thread& thread : m_threads)
	{
		thread = std::thread(&server::thread_process, this, thread_idx++);
	}
	gpr_log(GPR_INFO, "gRPC server running: threadiness=%zu", m_threads.size());

	while(server_impl::is_running())
	{
		sleep(1);
	}
	gpr_log(GPR_INFO, "gRPC server stopping");
	stop();
}

void falco::grpc::server::stop()
{
	gpr_log(GPR_INFO, "gRPC server shutting down");
	m_server->Shutdown();
	m_completion_queue->Shutdown();

	gpr_log(GPR_INFO, "gRPC server shutting down: waiting for the gRPC threads to complete");
	for(std::thread& t : m_threads)
	{
		if(t.joinable())
		{
			t.join();
		}
	}
	m_threads.clear();

	gpr_log(GPR_INFO, "gRPC server shutting down: draining all the remaining gRPC events");
	// Ignore remaining events
	void* ignore_tag = nullptr;
	bool ignore_ok = false;
	while(m_completion_queue->Next(&ignore_tag, &ignore_ok))
	{
	}

	gpr_log(GPR_INFO, "gRPC server shutting down: done");
}
