// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors

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

#include <google/protobuf/util/time_util.h>
#include "outputs_grpc.h"
#include "grpc_queue.h"
#include "falco_common.h"
#include "formats.h"

#if __has_attribute(deprecated)
#define DISABLE_WARNING_PUSH                        _Pragma("GCC diagnostic push")
#define DISABLE_WARNING_POP                         _Pragma("GCC diagnostic pop")
#define DISABLE_WARNING_DEPRECATED_DECLARATIONS     _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#elif defined(_MSC_VER)
#define DISABLE_WARNING_PUSH                        __pragma(warning(push))
#define DISABLE_WARNING_POP                         __pragma(warning(pop)) 
#define DISABLE_WARNING_DEPRECATED_DECLARATIONS     __pragma(warning(disable: 4996))
#else
#define DISABLE_WARNING_PUSH
#define DISABLE_WARNING_POP
#define DISABLE_WARNING_DEPRECATED_DECLARATIONS
#endif

void falco::outputs::output_grpc::output(const message *msg)
{
	falco::outputs::response grpc_res;

	// time
	auto timestamp = grpc_res.mutable_time();
	*timestamp = google::protobuf::util::TimeUtil::NanosecondsToTimestamp(msg->ts);

	// rule
	auto r = grpc_res.mutable_rule();
	*r = msg->rule;

	// source_deprecated (maintained for backward compatibility)
	// Setting this as reserved would cause old clients to receive the
	// 0-index enum element, which is the SYSCALL source in our case.
	// This can be misleading for clients with an old version of the
	// protobuf, so for now we deprecate the field and add a new PLUGIN
	// enum entry instead. 
	// todo(jasondellaluce): remove source_deprecated and reserve its number
	falco::schema::source s = falco::schema::source::SYSCALL;
	if(!falco::schema::source_Parse(msg->source, &s))
	{
		// unknown source names are expected to come from plugins
		s = falco::schema::source::PLUGIN;
	}
	DISABLE_WARNING_PUSH
	DISABLE_WARNING_DEPRECATED_DECLARATIONS
	grpc_res.set_source_deprecated(s);
	DISABLE_WARNING_POP

	// priority
	falco::schema::priority p = falco::schema::priority::EMERGENCY;
	if(!falco::schema::priority_Parse(falco_common::format_priority(msg->priority), &p))
	{
		throw falco_exception("Unknown priority passed to output_grpc::output()");
	}
	grpc_res.set_priority(p);

	// output
	auto output = grpc_res.mutable_output();
	*output = msg->msg;

	// output fields
	auto &fields = *grpc_res.mutable_output_fields();
	for(const auto &kv : msg->fields.items())
	{
		if (!kv.value().is_primitive())
		{
			throw falco_exception("output_grpc: output fields must be key-value maps");
		}
		fields[kv.key()] = (kv.value().is_string())
			? kv.value().get<std::string>()
			: kv.value().dump();
	}

	// hostname
	auto host = grpc_res.mutable_hostname();
	*host = m_hostname;

	// tags
	auto tags = grpc_res.mutable_tags();
	*tags = {msg->tags.begin(), msg->tags.end()};

	// source
	auto source = grpc_res.mutable_source();
	*source = msg->source;

	falco::grpc::queue::get().push(grpc_res);
}
