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

#include "config_falco.h"
#include "grpc_server_impl.h"
#include "falco_output_queue.h"
#include "logger.h"
#include "banned.h" // This raises a compilation error when certain functions are used

bool falco::grpc::server_impl::is_running()
{
	if(m_stop)
	{
		return false;
	}
	return true;
}

void falco::grpc::server_impl::get(const stream_context& ctx, const output::request& req, output::response& res)
{
	falco_logger::log(LOG_INFO, "get\n");
	if(ctx.m_status == stream_context::SUCCESS || ctx.m_status == stream_context::ERROR)
	{
		// todo(leodido) > log "status=ctx->m_status, stream=ctx->m_stream"
		ctx.m_stream = nullptr;
	}
	else
	{
		// Start or continue streaming
		// m_status == stream_context::STREAMING?
		// todo(leodido) > set m_stream
		falco_logger::log(LOG_INFO, "get - else\n");

		ctx.m_has_more = output::queue::get().unsafe_size() > 1;
		output::queue::get().try_pop(res);
	}
}

void falco::grpc::server_impl::sub(const bidi_context& ctx, const output::request& req, output::response& res)
{
	if(ctx.m_status == stream_context::SUCCESS || ctx.m_status == stream_context::ERROR)
	{
		return;
	}

	falco_logger::log(LOG_INFO, "SUB\n");
	ctx.m_has_more = output::queue::get().unsafe_size() > 0;

	if(ctx.m_has_more)
	{
		falco_logger::log(LOG_INFO, "SUB - HAS MORE? TRUE\n");
	}
	else
	{
		falco_logger::log(LOG_INFO, "SUB - HAS MORE? FALSE\n");
	}

	if(output::queue::get().try_pop(res))
	{
		falco_logger::log(LOG_INFO, "SUB - WAIT WRITE DONE: TRUE\n");
		ctx.m_wait_write_done = true;
	}
	else
	{
		falco_logger::log(LOG_INFO, "SUB - WAIT WRITE DONE: FALSE\n");
		ctx.m_wait_write_done = false;
	}
}

void falco::grpc::server_impl::version(const context& ctx, const version::request&, version::response& res)
{
	auto& build = *res.mutable_build();
	build = FALCO_VERSION_BUILD;

	auto& prerelease = *res.mutable_prerelease();
	prerelease = FALCO_VERSION_PRERELEASE;

	auto& version = *res.mutable_version();
	version = FALCO_VERSION;

	res.set_major(FALCO_VERSION_MAJOR);
	res.set_minor(FALCO_VERSION_MINOR);
	res.set_patch(FALCO_VERSION_PATCH);
}

void falco::grpc::server_impl::shutdown()
{
	m_stop = true;
}
