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

#include "falco_output_queue.h"
#include "falco_output.grpc.pb.h"
#include "grpc_context.h"

using namespace falco::output;

class falco_grpc_server_impl
{
public:
	falco_grpc_server_impl() = default;
	~falco_grpc_server_impl() = default;

protected:
	bool is_running();

	void subscribe(const stream_context& ctx, const request& req, response& res);

private:
	std::atomic<bool> m_stop{false};
};