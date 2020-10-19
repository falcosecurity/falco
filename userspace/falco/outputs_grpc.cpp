/*
Copyright (C) 2020 The Falco Authors

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
#include "banned.h" // This raises a compilation error when certain functions are used

void falco::outputs::output_grpc::output(const message *msg)
{
	falco::outputs::response grpc_res;

	// time
	auto timestamp = grpc_res.mutable_time();
	*timestamp = google::protobuf::util::TimeUtil::NanosecondsToTimestamp(msg->ts);

	// rule
	auto r = grpc_res.mutable_rule();
	*r = msg->rule;

	// source
	falco::schema::source s = falco::schema::source::SYSCALL;
	if(!falco::schema::source_Parse(msg->source, &s))
	{
		throw falco_exception("Unknown source passed to output_grpc::output_event()");
	}
	grpc_res.set_source(s);

	// priority
	falco::schema::priority p = falco::schema::priority::EMERGENCY;
	if(!falco::schema::priority_Parse(falco_common::priority_names[msg->priority], &p))
	{
		throw falco_exception("Unknown priority passed to output_grpc::output_event()");
	}
	grpc_res.set_priority(p);

	// output
	auto output = grpc_res.mutable_output();
	*output = msg->msg;

	// output fields
	auto &fields = *grpc_res.mutable_output_fields();
	for(const auto &kv : msg->fields)
	{
		fields[kv.first] = kv.second;
	}

	// hostname
	auto host = grpc_res.mutable_hostname();
	*host = m_hostname;

	falco::grpc::queue::get().push(grpc_res);
}