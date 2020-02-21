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

#include <string>

#ifdef GRPC_INCLUDE_IS_GRPCPP
#include <grpcpp/grpcpp.h>
#else
#include <grpc++/grpc++.h>
#endif

#include "grpc.pb.h"

namespace falco
{
namespace grpc
{

const std::string meta_session = "session_id";
const std::string meta_request = "request_id";

class context
{
public:
	context(::grpc::ServerContext* ctx);
	~context() = default;

	void get_metadata(std::string key, std::string& val);
	std::string peer() const;

	std::string m_prefix; // todo(leodido) > making this read only?

private:
	std::string m_session_id;
	std::string m_request_id;
	::grpc::ServerContext* m_ctx = nullptr;
};

class stream_context : public context
{
public:
	stream_context(::grpc::ServerContext* ctx):
		context(ctx){};
	~stream_context() = default;

	stream_status m_status = stream_status::STREAMING;

	mutable void* m_stream = nullptr; // todo(fntlnz, leodido) > useful in the future (request-specific stream data)
	mutable bool m_has_more = false;
};

} // namespace grpc
} // namespace falco
