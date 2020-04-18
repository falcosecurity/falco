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

#pragma once

#include <atomic>
#include "output.grpc.pb.h"
#include "version.grpc.pb.h"
#include "grpc_context.h"

namespace falco
{
namespace grpc
{
class server_impl
{
public:
	server_impl() = default;
	~server_impl() = default;

	void shutdown();

protected:
	bool is_running();

	void subscribe(const stream_context& ctx, const output::request& req, output::response& res);

	void version(const context& ctx, const version::request& req, version::response& res);

private:
	std::atomic<bool> m_stop{false};
};
} // namespace grpc
} // namespace falco
