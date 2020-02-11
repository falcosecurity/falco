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
#include "banned.h"

bool falco::grpc::server_impl::is_running()
{
	if(m_stop)
	{
		return false;
	}
	return true;
}

void falco::grpc::server_impl::outputs_impl(const stream_context& ctx, const outputs::request& req, outputs::response& res)
{
	std::string client = ctx.m_ctx->peer();
	if(ctx.m_status == stream_status::SUCCESS || ctx.m_status == stream_status::ERROR)
	{
		// Entering here when the streaming completed (request_context_base::FINISH)
		// context m_status == stream_context::SUCCESS when the gRPC server shutdown the context
		// context m_status == stream_context::ERROR when the gRPC client shutdown the context
		gpr_log(
			GPR_DEBUG,
			"server_impl::%s -> streaming done: %s, client=%s, status=%s, stream=%p",
			__func__,
			ctx.m_prefix.c_str(),
			client.c_str(),
			stream_status_Name(ctx.m_status).c_str(),
			ctx.m_stream);
		ctx.m_stream = nullptr;
	}
	else
	{
		// Start or continue streaming (m_status == stream_context::STREAMING)
		gpr_log(
			GPR_DEBUG,
			"server_impl::%s -> start or continue streaming: %s, client=%s, status=%s, stream=%p",
			__func__,
			ctx.m_prefix.c_str(),
			client.c_str(),
			stream_status_Name(ctx.m_status).c_str(),
			ctx.m_stream);
		// note(leodido) > set request-specific data on m_stream here, in case it is needed
		if(outputs::queue::get().try_pop(res) && !req.keepalive())
		{
			ctx.m_has_more = true;
			return;
		}
		while(is_running() && !outputs::queue::get().try_pop(res) && req.keepalive())
		{
		}

		ctx.m_has_more = !is_running() ? false : req.keepalive();
	}
}

void falco::grpc::server_impl::version_impl(const context& ctx, const version::request& req, version::response& res)
{
	std::string client = ctx.m_ctx->peer();
	gpr_log(GPR_DEBUG, "server_impl::%s -> replying: %s, client=%s", __func__, ctx.m_prefix.c_str(), client.c_str());

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
