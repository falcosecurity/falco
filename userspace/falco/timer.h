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

#include <chrono>

namespace utils
{
struct timer
{
	typedef std::chrono::steady_clock clock;
	typedef std::chrono::seconds seconds;

	void reset();

	unsigned long long seconds_elapsed() const;

private:
	clock::time_point start;
};
} // namespace utils
