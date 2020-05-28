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

#include "logger.h"
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
	// todo(leodido) > log "calling m_request_func: tag=this, state=m_state"
	(srv->m_output_svc.*m_request_func)(srvctx, &m_req, m_res_writer.get(), cq, cq, this);
}

template<>
void request_stream_context<falco::output::service, falco::output::request, falco::output::response>::process(server* srv)
{
	falco_logger::log(LOG_INFO, "process\n");
	// When it is the 1st process call
	if(m_state == request_context_base::REQUEST)
	{
		m_state = request_context_base::WRITE;
		m_stream_ctx.reset(new stream_context(m_srv_ctx.get()));
	}

	// Processing
	output::response res;
	(srv->*m_process_func)(*m_stream_ctx, m_req, res); // get()

	// When there are still more responses to stream
	if(m_stream_ctx->m_has_more)
	{
		// todo(leodido) > log "write: tag=this, state=m_state"
		m_res_writer->Write(res, this);
	}
	// No more responses to stream
	else
	{
		// Communicate to the gRPC runtime that we have finished.
		// The memory address of "this" instance uniquely identifies the event.
		m_state = request_context_base::FINISH;
		// todo(leodido) > log "finish: tag=this, state=m_state"
		m_res_writer->Finish(::grpc::Status::OK, this);
	}
}

template<>
void request_stream_context<falco::output::service, falco::output::request, falco::output::response>::end(server* srv, bool error)
{
	if(m_stream_ctx)
	{
		if(error)
		{
			// todo(leodido) > log error "error streaming: tag=this, state=m_state, stream=m_stream_ctx->m_stream"
		}
		m_stream_ctx->m_status = error ? stream_context::ERROR : stream_context::SUCCESS;

		// Complete the processing
		output::response res;
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
void falco::grpc::request_context<falco::version::service, falco::version::request, falco::version::response>::start(server* srv)
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
void falco::grpc::request_context<falco::version::service, falco::version::request, falco::version::response>::process(server* srv)
{
	version::response res;
	(srv->*m_process_func)(m_srv_ctx.get(), m_req, res);

	// Notify the gRPC runtime that this processing is done
	m_state = request_context_base::FINISH;
	// Using "this"- ie., the memory address of this context - to uniquely identify the event.
	m_res_writer->Finish(res, ::grpc::Status::OK, this);
}

template<>
void falco::grpc::request_context<falco::version::service, falco::version::request, falco::version::response>::end(server* srv, bool error)
{
	// todo(leodido) > handle processing errors here

	// Ask to start processing requests
	start(srv);
}

template<>
void request_bidi_context<falco::output::service, falco::output::request, falco::output::response>::start(server* srv)
{
	falco_logger::log(LOG_INFO, "REQUEST_BIDI_CONTEXT::START\n");
	m_state = request_context_base::REQUEST;
	m_srv_ctx.reset(new ::grpc::ServerContext);
	auto srvctx = m_srv_ctx.get();
	m_reader_writer.reset(new ::grpc::ServerAsyncReaderWriter<output::response, output::request>(srvctx));
	m_req.Clear();
	auto cq = srv->m_completion_queue.get();
	// Request to start processing given requests.
	// Using "this" - ie., the memory address of this context - as the tag that uniquely identifies the request.
	// In this way, different contexts can serve different requests concurrently.
	(srv->m_output_svc.*m_request_func)(srvctx, m_reader_writer.get(), cq, cq, this);
};

template<>
void request_bidi_context<falco::output::service, falco::output::request, falco::output::response>::process(server* srv)
{
	switch(m_state)
	{
	case request_context_base::REQUEST:
		falco_logger::log(LOG_INFO, "REQUEST_BIDI_CONTEXT::PROCESS - REQUEST\n");

		m_bidi_ctx.reset(new bidi_context(m_srv_ctx.get()));
		m_bidi_ctx->m_status = bidi_context::STREAMING;
		m_reader_writer->Read(&m_req, this); // todo > do we need this?
		m_state = request_context_base::WRITE;
		return;
	case request_context_base::WRITE:
		falco_logger::log(LOG_INFO, "REQUEST_BIDI_CONTEXT::PROCESS - WRITE\n");

		// m_reader_writer->Read(&m_req, this);
		// fixme > to debug: print the address of m_bidi_ctx - is it the same?
		if(!m_bidi_ctx->m_wait_write_done)
		{
			falco_logger::log(LOG_INFO, "REQUEST_BIDI_CONTEXT::PROCESS - WRITE - WAIT\n");
			// Processing
			output::response res;
			(srv->*m_process_func)(*m_bidi_ctx, m_req, res); // sub()
			if(m_bidi_ctx->m_has_more && m_bidi_ctx->m_wait_write_done)
			{
				m_bidi_ctx->m_wait_write_done = false;
				falco_logger::log(LOG_INFO, "WRITE(OUTFAKE)\n");
				m_reader_writer->Write(res, this);
			}
			else
			{
				if(m_bidi_ctx->m_has_more)
				{
					m_bidi_ctx->m_wait_write_done = false;
					falco_logger::log(LOG_INFO, "WRITE(OUTFAKEHASMORETRUEALTERNATIVEALTROCASO)\n");
					m_reader_writer->Write(res, this);
				}
				else
				{
					m_bidi_ctx->m_wait_write_done = false;
					falco_logger::log(LOG_INFO, "WRITE(OUTFAKEHASMORETRUEALTERNATIVEALTROCASO - WAIT TRUEEEEEEE)\n");
					m_reader_writer->Read(&m_req, this);
					m_state = request_context_base::WRITE;
				}
			}
		}

		return;
	case request_context_base::FINISH:
		falco_logger::log(LOG_INFO, "REQUEST_BIDI_CONTEXT::PROCESS - FINISH\n");
		return;
	default:
		falco_logger::log(LOG_INFO, "REQUEST_BIDI_CONTEXT::PROCESS - UNKNOWN\n");
		return;
	}
};

template<>
void request_bidi_context<falco::output::service, falco::output::request, falco::output::response>::end(server* srv, bool error)
{
	falco_logger::log(LOG_INFO, "REQUEST_BIDI_CONTEXT::END\n");

	// todo > error management? status management?
	// todo > when to call .Finish?

	if(m_bidi_ctx->m_has_more && m_bidi_ctx->m_wait_write_done)
	{
		falco_logger::log(LOG_INFO, "REQUEST_BIDI_CONTEXT::END - HAS MORE && WAIT_WRITE_DONE\n");
		falco_logger::log(LOG_INFO, "WRITE(OUT)\n");
		// m_reader_writer->Write(res, this); // fixme > how to get the processed res?
		m_bidi_ctx->m_wait_write_done = false;
	}
	else // todo > do we need to remove this else?
	{
		// m_bidi_ctx->m_status = bidi_context::STREAMING;
		// m_bidi_ctx->m_wait_write_done = true;
		start(srv);
	}
};

} // namespace grpc
} // namespace falco
