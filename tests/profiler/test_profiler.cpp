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
#include <hedley.h>

#include <cstdlib>
#include <iostream>

void profile_empty_func()
{
	PROFILEME();
}

// void profiler_test_do_work()
// {
// 	PROFILEME();
// 	std::this_thread::sleep_for(std::chrono::seconds(1));
// }

// void profiler_test_do_work2()
// {
// 	PROFILEME();
// 	profiler_test_do_work();
// 	std::this_thread::sleep_for(std::chrono::seconds(1));
// }

// TEST_CASE("profiler tests", "[profiler]")
// {
// 	SECTION("profiler needs to be allocated before usage")
// 	{
// 		alloc_chunk();
// 		REQUIRE(chunks.size() == 1);
// 		REQUIRE(labels.empty());
// 	}

// 	SECTION("calling a profiled function results in labels and chunks increase")
// 	{
// 		profiler_test_do_work();
// 		REQUIRE(labels.size() == 1);
// 		REQUIRE(chunks.size() == 1);
// 	}

// 	SECTION("calling just another profiled function that calls the one previously called should only increase labels by one")
// 	{
// 		profiler_test_do_work2();
// 		REQUIRE(labels.size() == 2);
// 		REQUIRE(chunks.size() == 1);
// 	}

// 	SECTION("clean")
// 	{
// 		labels.clear();
// 		chunks.clear();
// 		REQUIRE(labels.empty());
// 		REQUIRE(chunks.empty());
// 	}
// }

void BB()
{
	PROFILEME();
	std::this_thread::sleep_for(std::chrono::microseconds(1));
}

void AA()
{
	PROFILEME();
	BB();
	std::this_thread::sleep_for(std::chrono::microseconds(1));
}

void CC()
{
	PROFILEME();
	std::this_thread::sleep_for(std::chrono::microseconds(1));
}

void A()
{
	PROFILEME();
	AA();
	std::this_thread::sleep_for(std::chrono::microseconds(1));
	BB();
	std::this_thread::sleep_for(std::chrono::microseconds(1));
	CC();
	std::this_thread::sleep_for(std::chrono::microseconds(1));
	AA();
}

TEST_CASE("aaa", "[profiler]")
{
	alloc_chunk();
	A();

	for(std::vector<int>::size_type j = 0; j != chunks.size(); j++)
	{
		auto *c = chunks[j].begin;
		for(int i = 0; i < CHUNK_SIZE; i++) // i < 70
		{
			char b[1024];
			sprintf(b, "%ld - %03d: %u", j, i, c[i]);
			std::cout << std::string(b) << std::endl;
		}
	}

	// Ordine costruttori:
	// A
	//     AA1
	//         BB1
	//     BB2
	//     CC1
	//     AA2
	//         BB3

	// 2147483648 -> 0
	//      2147483649 -> 2147483648
	//           2147483650 -> 2147483649
	//      2147483650 -> 2147483648
	//      2147483651 -> 2147483648
	//      2147483649 -> 2147483648
	//           2147483650 -> 2147483649

	// Ordine distruttori:
	// BB1
	// AA1
	// BB2
	// CC1
	// BB3
	// AA2
	// A

	labels.clear();
	chunks.clear();
	REQUIRE(labels.empty());
	REQUIRE(chunks.empty());
}

TEST_CASE("ccc", "[profiler]")
{
	alloc_chunk();
	REQUIRE(chunks.size() == 1);

	size_t expected_chunks = 2;
	int how_many_times = (CHUNK_SIZE / CHUNK_ELEMENTS) * HEDLEY_STATIC_CAST(int, expected_chunks);

	// Use lt (<) to avoid pre-allocation of a new chunk at last element of previous chunk
	for(int i = 1; i < how_many_times; i++)
	{
		profile_empty_func();
	}

	REQUIRE(labels.size() == 1);
	REQUIRE(chunks.size() == expected_chunks);

	labels.clear();
	chunks.clear();
	REQUIRE(labels.empty());
	REQUIRE(chunks.empty());
}