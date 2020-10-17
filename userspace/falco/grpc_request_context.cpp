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
void request_stream_context<outputs::service, outputs::request, outputs::response>::start(server* srv)
{
	m_state = request_context_base::REQUEST;
	m_srv_ctx.reset(new ::grpc::ServerContext);
	auto srvctx = m_srv_ctx.get();
	m_res_writer.reset(new ::grpc::ServerAsyncWriter<outputs::response>(srvctx));
	m_stream_ctx.reset();
	m_req.Clear();
	auto cq = srv->m_completion_queue.get();
	// todo(leodido) > log "calling m_request_func: tag=this, state=m_state"
	(srv->m_output_svc.*m_request_func)(srvctx, &m_req, m_res_writer.get(), cq, cq, this);
}

template<>
void request_stream_context<outputs::service, outputs::request, outputs::response>::process(server* srv)
{
	// When it is the 1st process call
	if(m_state == request_context_base::REQUEST)
	{
		m_state = request_context_base::WRITE;
		m_stream_ctx.reset(new stream_context(m_srv_ctx.get()));
	}

	// Processing
	outputs::response res;
	(srv->*m_process_func)(*m_stream_ctx, m_req, res); // get()

	if(!m_stream_ctx->m_is_running)
	{
		m_state = request_context_base::FINISH;
		m_res_writer->Finish(::grpc::Status::OK, this);
		return;
	}

	// When there are still more responses to stream
	if(m_stream_ctx->m_has_more)
	{
		// todo(leodido) > log "write: tag=this, state=m_state"
		m_res_writer->Write(res, this);
		return;
	}

	// No more responses to stream
	// Communicate to the gRPC runtime that we have finished.
	// The memory address of "this" instance uniquely identifies the event.
	m_state = request_context_base::FINISH;
	// todo(leodido) > log "finish: tag=this, state=m_state"
	m_res_writer->Finish(::grpc::Status::OK, this);
}

template<>
void request_stream_context<outputs::service, outputs::request, outputs::response>::end(server* srv, bool error)
{
	if(m_stream_ctx)
	{
		if(error)
		{
			// todo(leodido) > log error "error streaming: tag=this, state=m_state, stream=m_stream_ctx->m_stream"
		}
		m_stream_ctx->m_status = error ? stream_context::ERROR : stream_context::SUCCESS;

		// Complete the processing
		outputs::response res;
		(srv->*m_process_func)(*m_stream_ctx, m_req, res); // get()
	}
	else
	{
		// Flow enters here when the processing of "m_request_func" fails.
		// Since this happens into the `start()` function, the processing does not advance to the `process()` function.
		// So, `m_stream_ctx` is null because it is set into the `process()` function.
		// The stream haven't started.

		// todo(leodido) > log error "ending streaming: tag=this, state=m_state, stream=null"
	}

	// Ask to start processing requests
	start(srv);
}

template<>
void request_context<version::service, version::request, version::response>::start(server* srv)
{
	m_state = request_context_base::REQUEST;
	m_srv_ctx.reset(new ::grpc::ServerContext);
	auto srvctx = m_srv_ctx.get();
	m_res_writer.reset(new ::grpc::ServerAsyncResponseWriter<version::response>(srvctx));
	m_req.Clear();
	auto cq = srv->m_completion_queue.get();
	// Request to start processing given requests.
	// Using "this" - ie., the memory address of this context - as the tag that uniquely identifies the request.
	// In this way, different contexts can serve different requests concurrently.
	(srv->m_version_svc.*m_request_func)(srvctx, &m_req, m_res_writer.get(), cq, cq, this);
}

template<>
void request_context<version::service, version::request, version::response>::process(server* srv)
{
	version::response res;
	(srv->*m_process_func)(m_srv_ctx.get(), m_req, res);

	// Notify the gRPC runtime that this processing is done
	m_state = request_context_base::FINISH;
	// Using "this"- ie., the memory address of this context - to uniquely identify the event.
	m_res_writer->Finish(res, ::grpc::Status::OK, this);
}

template<>
void request_context<version::service, version::request, version::response>::end(server* srv, bool error)
{
	// todo(leodido) > handle processing errors here

	// Ask to start processing requests
	start(srv);
}

template<>
void request_bidi_context<outputs::service, outputs::request, outputs::response>::start(server* srv)
{
	m_state = request_context_base::REQUEST;
	m_srv_ctx.reset(new ::grpc::ServerContext);
	auto srvctx = m_srv_ctx.get();
	m_reader_writer.reset(new ::grpc::ServerAsyncReaderWriter<outputs::response, outputs::request>(srvctx));
	m_req.Clear();
	auto cq = srv->m_completion_queue.get();
	// Request to start processing given requests.
	// Using "this" - ie., the memory address of this context - as the tag that uniquely identifies the request.
	// In this way, different contexts can serve different requests concurrently.
	(srv->m_output_svc.*m_request_func)(srvctx, m_reader_writer.get(), cq, cq, this);
};

template<>
void request_bidi_context<outputs::service, outputs::request, outputs::response>::process(server* srv)
{
	switch(m_state)
	{
	case request_context_base::REQUEST:
		m_bidi_ctx.reset(new bidi_context(m_srv_ctx.get()));
		m_bidi_ctx->m_status = bidi_context::STREAMING;
		m_state = request_context_base::WRITE;
		m_reader_writer->Read(&m_req, this);
		return;
	case request_context_base::WRITE:
		// Processing
		{
			outputs::response res;
			(srv->*m_process_func)(*m_bidi_ctx, m_req, res); // sub()

			if(!m_bidi_ctx->m_is_running)
			{
				m_state = request_context_base::FINISH;
				m_reader_writer->Finish(::grpc::Status::OK, this);
				return;
			}

			if(m_bidi_ctx->m_has_more)
			{
				m_state = request_context_base::WRITE;
				m_reader_writer->Write(res, this);
				return;
			}

			m_state = request_context_base::WRITE;
			m_reader_writer->Read(&m_req, this);
		}

		return;
	default:
		return;
	}
};

template<>
void request_bidi_context<outputs::service, outputs::request, outputs::response>::end(server* srv, bool error)
{
	if(m_bidi_ctx)
	{
		m_bidi_ctx->m_status = error ? bidi_context::ERROR : bidi_context::SUCCESS;

		// Complete the processing
		outputs::response res;
		(srv->*m_process_func)(*m_bidi_ctx, m_req, res); // sub()
	}

	// Ask to start processing requests
	start(srv);
};

} // namespace grpc
} // namespace falco
