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

#include "timer.h"

#include <chrono>

namespace utils
{
void timer::reset()
{
	start = clock::now();
}

unsigned long long timer::seconds_elapsed() const
{
	return std::chrono::duration_cast<seconds>(clock::now() - start).count();
}
} // namespace utils