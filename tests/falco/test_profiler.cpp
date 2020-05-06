/*
Copyright (C) 2020 The Falco Authors.

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
#include "profiler.h"
#include <catch.hpp>
#include <thread>
#include <chrono>

void profiler_test_do_work()
{
	PROFILEME();
	std::this_thread::sleep_for (std::chrono::seconds(1));
}

void profiler_test_do_work2()
{
	PROFILEME();
	std::this_thread::sleep_for (std::chrono::seconds(1));
}

TEST_CASE("profiler works", "[profiler]")
{
	alloc_chunk();
	profiler_test_do_work();
	profiler_test_do_work2();
	REQUIRE(labels.size() == 2);
}
