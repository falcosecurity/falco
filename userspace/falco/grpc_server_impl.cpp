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
#include "banned.h" // This raises a compilation error when certain functions are used

bool falco::grpc::server_impl::is_running()
{
	if(m_stop)
	{
		return false;
	}
	return true;
}

void falco::grpc::server_impl::subscribe(const stream_context& ctx, const output::request& req, output::response& res)
{
	if(ctx.m_status == stream_context::SUCCESS || ctx.m_status == stream_context::ERROR)
	{
		// todo(leodido) > log "status=ctx->m_status, stream=ctx->m_stream"
		ctx.m_stream = nullptr;
	}
	else
	{
		// Start or continue streaming
		// todo(leodido) > check for m_status == stream_context::STREAMING?
		// todo(leodido) > set m_stream
		if(!req.keepalive() && output::queue::get().try_pop(res))
		{
			ctx.m_has_more = true;
			return;
		}
		while(is_running() && req.keepalive() && !output::queue::get().try_pop(res))
		{
			usleep(200);
		}

		ctx.m_has_more = !is_running() ? false : req.keepalive();
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
