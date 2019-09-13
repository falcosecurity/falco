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

#include "falco_output.pb.h"
#include "tbb/concurrent_queue.h"

using namespace falco::output;

typedef tbb::concurrent_queue<response> falco_output_response_cq;

class falco_output_queue
{
public:
	static falco_output_queue& get()
	{
		static falco_output_queue instance;
		return instance;
	}

	bool try_pop(response& res)
	{
		return m_queue.try_pop(res);
	}

	void push(response& res)
	{
		m_queue.push(res);
	}

private:
	falco_output_queue()
	{
	}

	falco_output_response_cq m_queue;

	// We can use the better technique of deleting the methods we don't want.
public:
	falco_output_queue(falco_output_queue const&) = delete;
	void operator=(falco_output_queue const&) = delete;
};
