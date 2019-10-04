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

#include "grpc_request_context.h"

namespace falco
{
namespace grpc
{

template<>
void request_stream_context<falco::output::service, falco::output::request, falco::output::response>::start(server* srv)
{
	m_state = request_context_base::REQUEST;
	m_srv_ctx.reset(new ::grpc::ServerContext);
	auto srvctx = m_srv_ctx.get();
	m_res_writer.reset(new ::grpc::ServerAsyncWriter<output::response>(srvctx));
	m_stream_ctx.reset();
	m_req.Clear();
	auto cq = srv->m_completion_queue.get();
	(srv->m_output_svc.*m_request_func)(srvctx, &m_req, m_res_writer.get(), cq, cq, this);
}

template<>
void request_stream_context<falco::output::service, falco::output::request, falco::output::response>::process(server* srv)
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
void request_stream_context<falco::output::service, falco::output::request, falco::output::response>::end(server* srv, bool errored)
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

template<>
void falco::grpc::request_context<falco::version::service, falco::version::request, falco::version::response>::start(server* srv)
{
	m_state = request_context_base::REQUEST;
	m_srv_ctx.reset(new ::grpc::ServerContext);
	auto srvctx = m_srv_ctx.get();
	m_res_writer.reset(new ::grpc::ServerAsyncResponseWriter<version::response>(srvctx));
	m_req.Clear();
	auto cq = srv->m_completion_queue.get();
	(srv->m_version_svc.*m_request_func)(srvctx, &m_req, m_res_writer.get(), cq, cq, this);
}

template<>
void falco::grpc::request_context<falco::version::service, falco::version::request, falco::version::response>::process(server* srv)
{
	version::response res;
	(srv->*m_process_func)(m_srv_ctx.get(), m_req, res); // version()
	// Done
	m_state = request_context_base::FINISH;
	m_res_writer->Finish(res, ::grpc::Status::OK, this);
}

template<>
void falco::grpc::request_context<falco::version::service, falco::version::request, falco::version::response>::end(server* srv, bool errored)
{
	// todo(leodido) > what to do when errored is true?
	start(srv);
}

} // namespace grpc
} // namespace falco