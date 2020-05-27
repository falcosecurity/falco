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

private:
	::grpc::ServerContext* m_ctx = nullptr;
	std::string m_prefix;
};

class stream_context : public context
{
public:
	stream_context(::grpc::ServerContext* ctx):
		context(ctx){};
	~stream_context() = default;

	enum : char
	{
		STREAMING = 1,
		SUCCESS,
		ERROR
	} m_status = STREAMING;

	mutable void* m_stream = nullptr; // todo(fntlnz, leodido) > useful in the future
	mutable bool m_has_more = false;
};

class bidi_context : public context
{
public:
	bidi_context(::grpc::ServerContext* ctx):
		context(ctx){};
	~bidi_context() = default;

	enum : char
	{
		WAIT_CONNECT = 1,
		READY_TO_WRITE,
		WAIT_WRITE_DONE,
		FINISHED,
	} m_status = WAIT_CONNECT;

	mutable void* m_stream = nullptr; // todo(fntlnz, leodido) > useful in the future
	mutable bool m_has_more = false;  // fixme > needed?
};

} // namespace grpc
} // namespace falco
