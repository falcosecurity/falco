/*
Copyright (C) 2013-2019 Draios Inc dba Sysdig.

This file is part of sysdig.

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

#include <memory>
#ifdef GRPC_INCLUDE_IS_GRPCPP
#	include <grpcpp/grpcpp.h>
#else
#	include <grpc++/grpc++.h>
#endif

namespace libsinsp
{
class grpc_channel_registry
{
public:
	// Return a (shared) grpc::Channel for the provided url.
	static std::shared_ptr<grpc::Channel> get_channel(const std::string &url,
		const grpc::ChannelArguments *args = nullptr);

private:
	static std::map<std::string, std::weak_ptr<grpc::Channel>> s_channels;
};
}
