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

#pragma once

#include <atomic>

#include "tbb/concurrent_queue.h"
#include "falco_output.grpc.pb.h"
#include "falco_output.pb.h"
#include "grpc_context.h"

typedef tbb::concurrent_queue<falco_output_response> falco_output_response_cq;

class falco_grpc_server_impl
{
public:
	falco_grpc_server_impl() = default;
	~falco_grpc_server_impl() = default;

	falco_output_response_cq& m_event_queue;

	falco_grpc_server_impl(falco_output_response_cq& event_queue):
		m_event_queue(event_queue)
	{
	}

protected:
	bool is_running();

	void subscribe(const stream_context& ctx, const falco_output_request& req, falco_output_response& res);

private:
	std::atomic<bool> m_stop{false};
};