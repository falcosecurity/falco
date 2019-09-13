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

bool falco_grpc_server_impl::is_running()
{
	if(m_stop)
	{
		return false;
	}
	return true;
}

void falco_grpc_server_impl::subscribe(const stream_context& ctx, const request& req, response& res)
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
		if(falco_output_queue::get().try_pop(res) && !req.keepalive())
		{
			ctx.m_has_more = true;
			return;
		}
		while(!falco_output_queue::get().try_pop(res) && req.keepalive())
		{
		}

		ctx.m_has_more = req.keepalive();
	}
}
