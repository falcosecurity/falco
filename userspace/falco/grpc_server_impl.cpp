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

#include "grpc_server_impl.h"
#include "falco_output_queue.h"

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
		// todo > logic

		ctx.m_stream = nullptr;
	}
	else
	{
		// Start (or continue) streaming
		// ctx.m_status == stream_context::STREAMING
		if(output::queue::get().try_pop(res) && !req.keepalive())
		{
			ctx.m_has_more = true;
			return;
		}
		while(is_running() && !output::queue::get().try_pop(res) && req.keepalive())
		{
		}

		ctx.m_has_more = !is_running() ? false : req.keepalive();
	}
}

void falco::grpc::server_impl::shutdown()
{
	m_stop = true;
}
