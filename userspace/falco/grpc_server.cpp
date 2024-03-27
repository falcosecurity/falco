// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors

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

#include "config_falco.h"
#include "falco_engine.h"
#include "falco_engine_version.h"
#include "logger.h"
#include "grpc_server.h"
#include "grpc_queue.h"
#include "grpc_request_context.h"
#include "falco_utils.h"

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

#define REGISTER_BIDI(req, res, svc, rpc, impl, num)                          \
	std::vector<request_bidi_context<svc, req, res>> rpc##_contexts(num); \
	for(request_bidi_context<svc, req, res> & c : rpc##_contexts)         \
	{                                                                     \
		c.m_process_func = &server::impl;                             \
		c.m_request_func = &svc::AsyncService::Request##rpc;          \
		c.start(this);                                                \
	}

static void gpr_log_dispatcher_func(gpr_log_func_args* args)
{
	falco_logger::level priority;
	switch(args->severity)
	{
	case GPR_LOG_SEVERITY_ERROR:
		priority = falco_logger::level::ERR;
		break;
	case GPR_LOG_SEVERITY_DEBUG:
		priority = falco_logger::level::DEBUG;
		break;
	default:
		priority = falco_logger::level::INFO;
		break;
	}

	std::string copy = "grpc: ";
	copy.append(args->message);
	copy.push_back('\n');
	falco_logger::log(priority, std::move(copy));
}

void falco::grpc::server::thread_process(int thread_index)
{
	void* tag = nullptr;
	bool event_read_success = false;
	while(m_completion_queue->Next(&tag, &event_read_success))
	{
		if(tag == nullptr)
		{
			// todo(leodido) > log error "server completion queue error: empty tag"
			continue;
		}

		// Obtain the context for a given tag
		request_context_base* ctx = static_cast<request_context_base*>(tag);

		// todo(leodido) > log "next event: tag=tag, read_success=event_read_success, state=ctx->m_state"

		// When event has not been read successfully
		if(!event_read_success)
		{
			if(ctx->m_state != request_context_base::REQUEST)
			{
				// todo(leodido) > log error "server completion queue failing to read: tag=tag"

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
			// todo(leodido) > log error "unknown completion queue event: tag=tag, state=ctx->m_state"
			break;
		}

		// todo(leodido) > log "thread completed: index=thread_index"
	}
}

void falco::grpc::server::init(
	const std::string& server_addr,
	int threadiness,
	const std::string& private_key,
	const std::string& cert_chain,
	const std::string& root_certs,
	const std::string& log_level)
{
	m_server_addr = server_addr;
	m_threadiness = threadiness;
	m_private_key = private_key;
	m_cert_chain = cert_chain;
	m_root_certs = root_certs;

	// Set the verbosity level of gpr logger
	falco::schema::priority logging_level = falco::schema::INFORMATIONAL;
	falco::schema::priority_Parse(log_level, &logging_level);
	switch(logging_level)
	{
	case falco::schema::ERROR:
		gpr_set_log_verbosity(GPR_LOG_SEVERITY_ERROR);
		break;
	case falco::schema::DEBUG:
		gpr_set_log_verbosity(GPR_LOG_SEVERITY_DEBUG);
		break;
	case falco::schema::INFORMATIONAL:
	default:
		// note > info will always enter here since it is != from "informational"
		gpr_set_log_verbosity(GPR_LOG_SEVERITY_INFO);
		break;
	}
	gpr_log_verbosity_init();
	gpr_set_log_function(gpr_log_dispatcher_func);

	if(falco::utils::network::is_unix_scheme(m_server_addr))
	{
		init_unix_server_builder();
		return;
	}
	init_mtls_server_builder();
}

void falco::grpc::server::init_mtls_server_builder()
{
	std::string private_key;
	std::string cert_chain;
	std::string root_certs;
	falco::utils::readfile(m_cert_chain, cert_chain);
	falco::utils::readfile(m_private_key, private_key);
	falco::utils::readfile(m_root_certs, root_certs);
	::grpc::SslServerCredentialsOptions::PemKeyCertPair cert_pair{private_key, cert_chain};
	::grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
	ssl_opts.pem_root_certs = root_certs;
	ssl_opts.pem_key_cert_pairs.push_back(cert_pair);

	m_server_builder.AddListeningPort(m_server_addr, ::grpc::SslServerCredentials(ssl_opts));
}

void falco::grpc::server::init_unix_server_builder()
{
	m_server_builder.AddListeningPort(m_server_addr, ::grpc::InsecureServerCredentials());
}

void falco::grpc::server::run()
{
	m_server_builder.RegisterService(&m_output_svc);
	m_server_builder.RegisterService(&m_version_svc);

	m_completion_queue = m_server_builder.AddCompletionQueue();
	m_server = m_server_builder.BuildAndStart();
	if(m_server == nullptr)
	{
		falco_logger::log(falco_logger::level::EMERG, "Error starting gRPC server\n");
		return;
	}
	falco_logger::log(falco_logger::level::INFO, "Starting gRPC server at " + m_server_addr + "\n");

	// The number of contexts is multiple of the number of threads
	// This defines the number of simultaneous completion queue requests of the same type (service::AsyncService::Request##RPC)
	// For this approach to be sufficient server::IMPL have to be fast
	int context_num = m_threadiness * 10;
	// todo(leodido) > take a look at thread_stress_test.cc into grpc repository

	REGISTER_UNARY(version::request, version::response, version::service, version, version, context_num)
	REGISTER_STREAM(outputs::request, outputs::response, outputs::service, get, get, context_num)
	REGISTER_BIDI(outputs::request, outputs::response, outputs::service, sub, sub, context_num)

	m_threads.resize(m_threadiness);
	int thread_idx = 0;
	for(std::thread& thread : m_threads)
	{
		thread = std::thread(&server::thread_process, this, thread_idx++);
	}
	// todo(leodido) > log "gRPC server running: threadiness=m_threads.size()"

	m_server->Wait();
	// todo(leodido) > log "stopping gRPC server"
	stop();
}

void falco::grpc::server::stop()
{
	falco_logger::log(falco_logger::level::INFO, "Shutting down gRPC server. Waiting until external connections are closed by clients\n");
	m_completion_queue->Shutdown();

	falco_logger::log(falco_logger::level::INFO, "Waiting for the gRPC threads to complete\n");
	for(std::thread& t : m_threads)
	{
		if(t.joinable())
		{
			t.join();
		}
	}
	m_threads.clear();

	falco_logger::log(falco_logger::level::INFO, "Draining all the remaining gRPC events\n");
	// Ignore remaining events
	void* ignore_tag = nullptr;
	bool ignore_ok = false;
	while(m_completion_queue->Next(&ignore_tag, &ignore_ok))
	{
	}

	falco_logger::log(falco_logger::level::INFO, "Shutting down gRPC server complete\n");
}

bool falco::grpc::server::is_running()
{
	if(m_stop)
	{
		return false;
	}
	return true;
}

void falco::grpc::server::get(const stream_context& ctx, const outputs::request& req, outputs::response& res)
{
	if(ctx.m_status == stream_context::SUCCESS || ctx.m_status == stream_context::ERROR)
	{
		// todo(leodido) > log "status=ctx->m_status, stream=ctx->m_stream"
		ctx.m_stream = nullptr;
		return;
	}

	ctx.m_is_running = is_running();

	// Start or continue streaming
	// m_status == stream_context::STREAMING?
	// todo(leodido) > set m_stream

	ctx.m_has_more = queue::get().try_pop(res);
}

void falco::grpc::server::sub(const bidi_context& ctx, const outputs::request& req, outputs::response& res)
{
	if(ctx.m_status == stream_context::SUCCESS || ctx.m_status == stream_context::ERROR)
	{
		ctx.m_stream = nullptr;
		return;
	}

	ctx.m_is_running = is_running();

	// Start or continue streaming
	// m_status == stream_context::STREAMING?
	// todo(leodido) > set m_stream

	ctx.m_has_more = queue::get().try_pop(res);
}

void falco::grpc::server::version(const context& ctx, const version::request&, version::response& res)
{
	auto& build = *res.mutable_build();
	build = FALCO_VERSION_BUILD;

	auto& prerelease = *res.mutable_prerelease();
	prerelease = FALCO_VERSION_PRERELEASE;

	auto& version = *res.mutable_version();
	version = FALCO_VERSION;

	res.set_engine_version(FALCO_ENGINE_VERSION);
	res.set_engine_fields_checksum(FALCO_ENGINE_CHECKSUM); 
	auto engine_version = falco_engine::engine_version();
	res.set_engine_major(engine_version.major());
	res.set_engine_minor(engine_version.minor());
	res.set_engine_patch(engine_version.patch());

	res.set_major(FALCO_VERSION_MAJOR);
	res.set_minor(FALCO_VERSION_MINOR);
	res.set_patch(FALCO_VERSION_PATCH);
}

void falco::grpc::server::shutdown()
{
	m_stop = true;
	m_server->Shutdown();
}
