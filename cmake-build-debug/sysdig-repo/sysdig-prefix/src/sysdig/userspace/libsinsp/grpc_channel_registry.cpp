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

#include "grpc_channel_registry.h"


std::map<std::string, std::weak_ptr<grpc::Channel>> libsinsp::grpc_channel_registry::s_channels;

std::shared_ptr<grpc::Channel> libsinsp::grpc_channel_registry::get_channel(const std::string &url, const grpc::ChannelArguments *args)
{
	std::shared_ptr<grpc::Channel> chan;
	auto it = s_channels.find(url);
	if(it != s_channels.end())
	{
		chan = it->second.lock();
		if (chan != nullptr)
		{
			return chan;
		}
	}
	if (args)
	{
		chan = grpc::CreateCustomChannel(url,
			grpc::InsecureChannelCredentials(), *args);
	}
	else
	{
		chan = grpc::CreateChannel(url,
			grpc::InsecureChannelCredentials());
	}
	s_channels[url] = chan;

	return chan;
}
