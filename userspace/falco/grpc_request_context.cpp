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
void request_stream_context<falco::outputs::service, falco::outputs::request, falco::outputs::response>::start(server* srv)
{
	m_state = request_state::REQUEST;
	m_srv_ctx.reset(new ::grpc::ServerContext);
	auto srvctx = m_srv_ctx.get();
	m_res_writer.reset(new ::grpc::ServerAsyncWriter<outputs::response>(srvctx));
	m_stream_ctx.reset();
	m_req.Clear();
	auto cq = srv->m_completion_queue.get();
	// m_stream_ctx->m_stream = this; // todo(leodido) > save the tag - ie., this - into the stream?
	gpr_log(
		GPR_DEBUG,
		"request_stream_context<outputs>::%s -> m_request_func: tag=%p, state=%s",
		__func__,
		this,
		request_state_Name(m_state).c_str());
	(srv->m_outputs_svc.*m_request_func)(srvctx, &m_req, m_res_writer.get(), cq, cq, this);
}

template<>
void request_stream_context<falco::outputs::service, falco::outputs::request, falco::outputs::response>::process(server* srv)
{
	// When it is the 1st process call
	if(m_state == request_state::REQUEST)
	{
		m_state = request_state::WRITE;
		m_stream_ctx.reset(new stream_context(m_srv_ctx.get()));
	}

	// Processing
	gpr_log(
		GPR_DEBUG,
		"request_stream_context<outputs>::%s -> m_process_func: tag=%p, state=%s",
		__func__,
		this,
		request_state_Name(m_state).c_str());

	outputs::response res;
	// fixme(leodido) > srv->m_outputs_svc?
	(srv->*m_process_func)(*m_stream_ctx, m_req, res); // outputs()

	// When there are still more responses to stream
	if(m_stream_ctx->m_has_more)
	{
		gpr_log(
			GPR_DEBUG,
			"request_stream_context<outputs>::%s -> write: tag=%p, state=%s",
			__func__,
			this,
			request_state_Name(m_state).c_str());
		m_res_writer->Write(res, this);
	}
	// No more responses to stream
	else
	{
		// Communicate to the gRPC runtime that we have finished.
		// The memory address of "this" instance uniquely identifies the event.
		m_state = request_state::FINISH;
		gpr_log(
			GPR_DEBUG,
			"request_stream_context<outputs>::%s -> finish: tag=%p, state=finish",
			__func__,
			this);

		m_res_writer->Finish(::grpc::Status::OK, this);
	}
}

template<>
void request_stream_context<falco::outputs::service, falco::outputs::request, falco::outputs::response>::end(server* srv, bool errored)
{
	if(m_stream_ctx)
	{
		if(errored)
		{
			gpr_log(
				GPR_ERROR,
				"request_stream_context<outputs>::%s -> error streaming: tag=%p, state=%s, stream=%p",
				__func__,
				this,
				request_state_Name(m_state).c_str(),
				m_stream_ctx->m_stream);
		}
		m_stream_ctx->m_status = errored ? stream_status::ERROR : stream_status::SUCCESS;

		// Complete the processing
		outputs::response res;
		(srv->*m_process_func)(*m_stream_ctx, m_req, res); // outputs()
	}
	else
	{
		// Flow enters here when the processing of "m_request_func" fails.
		// Since this happens into the `start()` function, the processing does not advance to the `process()` function.
		// So, `m_stream_ctx` is null because it is set into the `process()` function.
		// The stream haven't started.

		gpr_log(
			GPR_ERROR,
			"%s -> ending streaming: tag=%p, state=%s, stream=never started",
			__func__,
			this,
			request_state_Name(m_state).c_str());
	}

	// Ask to start processing requests
	start(srv);
}

template<>
void falco::grpc::request_context<falco::version::service, falco::version::request, falco::version::response>::start(server* srv)
{
	m_state = request_state::REQUEST;
	m_srv_ctx.reset(new ::grpc::ServerContext);
	auto srvctx = m_srv_ctx.get();
	m_res_writer.reset(new ::grpc::ServerAsyncResponseWriter<version::response>(srvctx));
	m_req.Clear();
	auto cq = srv->m_completion_queue.get();
	// Request to start processing given requests.
	// Using "this" - ie., the memory address of this context - as the tag that uniquely identifies the request.
	// In this way, different contexts can serve different requests concurrently.
	gpr_log(
		GPR_DEBUG,
		"request_context<version>::%s -> m_request_func: tag=%p, state=%s",
		__func__,
		this,
		request_state_Name(m_state).c_str());
	(srv->m_version_svc.*m_request_func)(srvctx, &m_req, m_res_writer.get(), cq, cq, this);
}

template<>
void falco::grpc::request_context<falco::version::service, falco::version::request, falco::version::response>::process(server* srv)
{
	gpr_log(
		GPR_DEBUG,
		"request_context<version>::%s -> m_process_func: tag=%p, state=%s",
		__func__,
		this,
		request_state_Name(m_state).c_str());

	version::response res;
	(srv->*m_process_func)(m_srv_ctx.get(), m_req, res);

	// Notify the gRPC runtime that this processing is done
	m_state = request_state::FINISH;
	// Using "this"- ie., the memory address of this context - to uniquely identify the event.
	m_res_writer->Finish(res, ::grpc::Status::OK, this);
}

template<>
void falco::grpc::request_context<falco::version::service, falco::version::request, falco::version::response>::end(server* srv, bool errored)
{
	if(errored)
	{
		gpr_log(
			GPR_ERROR,
			"request_context<version>::%s -> error replying: tag=%p, state=%s",
			__func__,
			this,
			request_state_Name(m_state).c_str());
	}

	// Ask to start processing requests
	start(srv);
}

} // namespace grpc
} // namespace falco