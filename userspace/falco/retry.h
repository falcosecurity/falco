/*
Copyright (C) 2016-2019 Draios Inc dba Sysdig.

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

#include "logger.h"

#include <algorithm>
#include <type_traits>
#include <chrono>
#include <iostream>
#include <thread>

namespace utils
{
template<
	typename Predicate,
	typename Callable,
	typename... Args,
	// figure out what the callable returns
	typename R = std::decay_t<std::result_of_t<Callable &(Args...)>>,
	// require that Predicate is actually a Predicate
	std::enable_if_t<std::is_convertible<std::result_of_t<Predicate &(R)>, bool>::value, int> = 0>
R retry(int max_retries,
	uint64_t initial_delay_ms,
	uint64_t max_backoff_ms,
	Predicate &&retriable,
	Callable &&callable,
	Args &&... args)
{
	int retries = 0;
	while(true)
	{
		falco_logger::log(LOG_INFO, "Retry no.: " + std::to_string(retries) + "\n");
		bool result = callable(std::forward<Args>(args)...);

		if(!retriable(result))
		{
			return result;
		}
		if(retries >= max_retries)
		{
			return result;
		}
		int64_t delay = 0;
		if(initial_delay_ms > 0)
		{
			delay = std::min(initial_delay_ms << retries, max_backoff_ms);
		}

		std::ostringstream message;
		message << "Waiting " << delay << "ms ... \n";
		falco_logger::log(LOG_INFO, message.str());
		std::this_thread::sleep_for(std::chrono::milliseconds(delay));
		retries++;
	}
}
}