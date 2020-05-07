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

void profiler_test_do_experiment()
{
	PROFILEME();
}

void profiler_test_do_work()
{
	PROFILEME();
	std::this_thread::sleep_for(std::chrono::seconds(1));
}

void profiler_test_do_work2()
{
	PROFILEME();
	profiler_test_do_work();
	std::this_thread::sleep_for(std::chrono::seconds(1));
}

TEST_CASE("profiler tests", "[profiler]")
{
	SECTION("profiler needs to be allocated before usage")
	{
		alloc_chunk();
		REQUIRE(chunks.size() == 1);
		REQUIRE(labels.empty());
	}

	SECTION("calling a profiled function results in labels and chunks increase")
	{
		profiler_test_do_work();
		REQUIRE(labels.size() == 1);
		REQUIRE(chunks.size() == 1);
	}

	SECTION("calling just another profiled function that calls the one previously called should only increase labels by one")
	{
		profiler_test_do_work2();
		REQUIRE(labels.size() == 2);
		REQUIRE(chunks.size() == 1);
	}

	SECTION("clean")
	{
		labels.clear();
		chunks.clear();
		REQUIRE(labels.empty());
		REQUIRE(chunks.empty());
	}
}

TEST_CASE("consecutive chunks allocation", "[profiler]")
{
	int expected_chunks = 10;
	alloc_chunk();
	for(int i = chunks.size(); i < (CHUNK_SIZE / 5) * expected_chunks; i++)
	{
		profiler_test_do_experiment();
	}

	REQUIRE(labels.size() == 1);
	REQUIRE(chunks.size() == expected_chunks);

	labels.clear();
	chunks.clear();

	REQUIRE(labels.empty());
	REQUIRE(chunks.empty());
}
