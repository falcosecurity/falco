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

#ifdef GRPC_INCLUDE_IS_GRPCPP
#include <grpcpp/grpcpp.h>
#else
#include <grpc++/grpc++.h>
#endif

#include "logger.h"
#include "grpc_server.h"
#include "grpc_context.h"
#include "utils.h"
#include "banned.h"

// todo(leodido) > remove this macro doing only one REGISTER macro (only the context typeschange and they inherit from a base class)

#define REGISTER_STREAM(req, res, svc, rpc, impl, num)                     \
	std::vector<request_stream_context<req, res>> rpc##_contexts(num); \
	for(request_stream_context<req, res> & c : rpc##_contexts)         \
	{                                                                  \
		c.m_process_func = &server::impl;                          \
		c.m_request_func = &svc::AsyncService::Request##rpc;       \
		c.start(this);                                             \
	}

#define REGISTER_UNARY(req, res, svc, rpc, impl, num)                \
	std::vector<request_context<req, res>> rpc##_contexts(num);  \
	for(request_context<req, res> & c : rpc##_contexts)          \
	{                                                            \
		c.m_process_func = &server::impl;                    \
		c.m_request_func = &svc::AsyncService::Request##rpc; \
		c.start(this);                                       \
	}

namespace falco
{
namespace grpc
{

template<>
void request_stream_context<falco::output::request, falco::output::response>::start(server* srv)
{
	m_state = request_context_base::REQUEST;
	m_srv_ctx.reset(new ::grpc::ServerContext);
	auto srvctx = m_srv_ctx.get();
	m_res_writer.reset(new ::grpc::ServerAsyncWriter<output::response>(srvctx));
	m_stream_ctx.reset();
	m_req.Clear();
	auto cq = srv->m_completion_queue.get();
	(srv->m_svc.*m_request_func)(srvctx, &m_req, m_res_writer.get(), cq, cq, this);
}

template<>
void request_stream_context<falco::output::request, falco::output::response>::process(server* srv)
{
	// When it is the 1st process call
	if(m_state == request_context_base::REQUEST)
	{
		m_state = request_context_base::WRITE;
		m_stream_ctx.reset(new stream_context(m_srv_ctx.get()));
	}

	// Processing
	output::response res;
	(srv->*m_process_func)(*m_stream_ctx, m_req, res); // subscribe()

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
		m_res_writer->Finish(::grpc::Status::OK, this);
	}
}

template<>
void request_stream_context<falco::output::request, falco::output::response>::end(server* srv, bool errored)
{
	if(m_stream_ctx)
	{
		m_stream_ctx->m_status = errored ? stream_context::ERROR : stream_context::SUCCESS;

		// Complete the processing
		output::response res;
		(srv->*m_process_func)(*m_stream_ctx, m_req, res); // subscribe()
	}

	start(srv);
}
} // namespace grpc
} // namespace falco

template<>
void falco::grpc::request_context<falco::version::service, falco::version::request, falco::version::response>::start(server* srv)
{
	m_state = request_context_base::REQUEST;
	m_srv_ctx.reset(new ::grpc::ServerContext);
	auto srvctx = m_srv_ctx.get();
	m_res_writer.reset(new ::grpc::ServerAsyncWriter<version::response>(srvctx));
	m_req.Clear();
	// auto cq = srv->m_completion_queue.get();
	// fixme(leodido) > m_svc is output::service not version::service
	// (srv->m_svc.*m_request_func)(srvctx, &m_req, m_res_writer.get(), cq, cq, this);
}

template<>
void falco::grpc::request_context<falco::version::service, falco::version::request, falco::version::response>::process(server* srv)
{
	version::response res;
	(srv->*m_process_func)(m_srv_ctx.get(), m_req, res);
	// Done
	m_state = request_context_base::FINISH;
	m_res_writer->Write(res, this);
	m_res_writer->Finish(::grpc::Status::OK, this);
}

template<>
void falco::grpc::request_context<falco::version::service, falco::version::request, falco::version::response>::end(server* srv, bool errored)
{
	// todo(leodido) > what to do when errored is true?
	start(srv);
}

void falco::grpc::server::thread_process(int thread_index)
{
	void* tag = nullptr;
	bool event_read_success = false;
	while(m_completion_queue->Next(&tag, &event_read_success))
	{
		if(tag == nullptr)
		{
			continue;
		}

		// Obtain the context for a given tag
		request_context_base* ctx = static_cast<request_context_base*>(tag);

		// When event has not been read successfully
		if(!event_read_success)
		{
			if(ctx->m_state != request_context_base::REQUEST)
			{
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
			break;
		default:
			// todo > log "unkown completion queue event"
			break;
		}
	}
}

void falco::grpc::server::init(std::string server_addr, int threadiness, std::string private_key, std::string cert_chain, std::string root_certs)
{
	m_server_addr = server_addr;
	m_threadiness = threadiness;
	m_private_key = private_key;
	m_cert_chain = cert_chain;
	m_root_certs = root_certs;
}

void falco::grpc::server::run()
{
	string private_key;
	string cert_chain;
	string root_certs;

	falco::utils::read(m_cert_chain, cert_chain);
	falco::utils::read(m_private_key, private_key);
	falco::utils::read(m_root_certs, root_certs);

	::grpc::SslServerCredentialsOptions::PemKeyCertPair cert_pair{private_key, cert_chain};

	::grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
	ssl_opts.pem_root_certs = root_certs;
	ssl_opts.pem_key_cert_pairs.push_back(cert_pair);

	::grpc::ServerBuilder builder;
	builder.AddListeningPort(m_server_addr, ::grpc::SslServerCredentials(ssl_opts));
	builder.RegisterService(&m_svc);
	// fixme(leodido) > register various services ...

	m_completion_queue = builder.AddCompletionQueue();
	m_server = builder.BuildAndStart();
	falco_logger::log(LOG_INFO, "Starting gRPC server at " + m_server_addr + "\n");

	// The number of contexts is multiple of the number of threads
	// This defines the number of simultaneous completion queue requests of the same type (service::AsyncService::Request##RPC)
	// For this approach to be sufficient server::IMPL have to be fast
	int context_num = m_threadiness * 10;

	// REGISTER_UNARY(version::request, version::response, version::service, version, version, context_num)
	REGISTER_STREAM(output::request, output::response, output::service, subscribe, subscribe, context_num)

	m_threads.resize(m_threadiness);
	int thread_idx = 0;
	for(std::thread& thread : m_threads)
	{
		thread = std::thread(&server::thread_process, this, thread_idx++);
	}

	while(server_impl::is_running())
	{
		sleep(1);
	}
	stop();
}

void falco::grpc::server::stop()
{
	falco_logger::log(LOG_INFO, "Shutting down gRPC server. Waiting until external connections are closed by clients\n");
	m_server->Shutdown();
	m_completion_queue->Shutdown();

	falco_logger::log(LOG_INFO, "Waiting for the gRPC threads to complete\n");
	for(std::thread& t : m_threads)
	{
		if(t.joinable())
		{
			t.join();
		}
	}
	m_threads.clear();

	falco_logger::log(LOG_INFO, "Ignoring all the remaining gRPC events\n");
	// Ignore remaining events
	void* ignore_tag = nullptr;
	bool ignore_ok = false;
	while(m_completion_queue->Next(&ignore_tag, &ignore_ok))
	{
	}

	falco_logger::log(LOG_INFO, "Shutting down gRPC server complete\n");
}
