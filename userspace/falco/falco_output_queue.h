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

#include "output.pb.h"
#include "tbb/concurrent_queue.h"

namespace falco
{
namespace output
{
typedef tbb::concurrent_queue<response> response_cq;

class queue
{
public:
	static queue& get()
	{
		static queue instance;
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
	queue()
	{
	}

	response_cq m_queue;

	// We can use the better technique of deleting the methods we don't want.
public:
	queue(queue const&) = delete;
	void operator=(queue const&) = delete;
};
} // namespace output
} // namespace falco
