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

#include <sstream>

#include "grpc_context.h"

context::context(grpc::ServerContext* ctx):
	m_ctx(ctx)
{
	std::string session_id;
	std::string request_id;

	get_metadata(meta_session, session_id);
	get_metadata(meta_session, request_id);

	std::stringstream meta;
	if(!session_id.empty())
	{
		meta << "[sid=" << session_id << "]";
	}

	if(!request_id.empty())
	{
		meta << "[rid=" << request_id << "]";
	}
}

void context::get_metadata(std::string key, std::string& val)
{
	const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata = m_ctx->client_metadata();
	auto it = client_metadata.find(key);
	if(it != client_metadata.end())
	{
		val.assign(it->second.data(), it->second.size());
	}
}