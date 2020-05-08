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
#include <algorithm>
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

void bb()
{
	PROFILEME();
	std::this_thread::sleep_for(std::chrono::microseconds(1));
}

void aa()
{
	PROFILEME();
	bb();
	std::this_thread::sleep_for(std::chrono::microseconds(1));
}

void cc()
{
	PROFILEME();
	std::this_thread::sleep_for(std::chrono::microseconds(1));
}

void profiler_fake_root_func()
{
	PROFILEME();
	aa();
	std::this_thread::sleep_for(std::chrono::microseconds(1));
	bb();
	std::this_thread::sleep_for(std::chrono::microseconds(1));
	cc();
	std::this_thread::sleep_for(std::chrono::microseconds(1));
	aa();
}

TEST_CASE("parents - single chunk", "[profiler]")
{
	alloc_chunk();
	profiler_fake_root_func();

	REQUIRE(labels.size() == 4);
	REQUIRE(chunks.size() == 1);
	REQUIRE(chunks[0].begin[5] == 0); // profiler_fake_root_func is root (parent = 0)

	auto predicate = [](int x) {
		return [=](const label &l) {
			return l.label == chunks[0].begin[x];
		};
	};

	// Ctor ordering:
	// profile_fake_root
	//     AA1
	//         BB1
	//     BB2
	//     CC1
	//     AA2
	//         BB3

	// Dtor ordering:
	// BB1
	// AA1
	// BB2
	// CC1
	// BB3
	// AA2
	// profile_fake_root

	auto root = std::find_if(std::begin(labels), std::end(labels), predicate(0));
	REQUIRE(root->func == "profiler_fake_root_func"); // function name is "profiler_fake_root_func"
	REQUIRE(chunks[0].begin[5 + CHUNK_ELEMENTS] == root->label); // aa (call aa1) has parent "profiler_fake_root_func"

	{
		auto it = std::find_if(std::begin(labels), std::end(labels), predicate(CHUNK_ELEMENTS));
		REQUIRE(it->func == "aa"); // function name is "aa" (call aa1)
		REQUIRE(chunks[0].begin[5 + (2 * CHUNK_ELEMENTS)] == it->label); // bb (call bb1) has parent "aa" (call aa1)
	}

	{
		auto it = std::find_if(std::begin(labels), std::end(labels), predicate(2 * CHUNK_ELEMENTS));
		REQUIRE(it->func == "bb"); // function name is "bb" (call bb1)
		REQUIRE(chunks[0].begin[5 + (3 * CHUNK_ELEMENTS)] == root->label); // bb (call bb2) has parent "profiler_fake_root_func"
	}

	{
		auto it = std::find_if(std::begin(labels), std::end(labels), predicate(3 * CHUNK_ELEMENTS));
		REQUIRE(it->func == "bb"); // function name is "bb" (call bb2)
		REQUIRE(chunks[0].begin[5 + (4 * CHUNK_ELEMENTS)] == root->label); // cc (call cc1) has parent "profiler_fake_root_func"
	}

	{
		auto it = std::find_if(std::begin(labels), std::end(labels), predicate(4 * CHUNK_ELEMENTS));
		REQUIRE(it->func == "cc"); // function name is "cc" (call cc1)
		REQUIRE(chunks[0].begin[5 + (5 * CHUNK_ELEMENTS)] == root->label); // aa (call aa2) has parent "profiler_fake_root_func"
	}

	{
		auto it = std::find_if(std::begin(labels), std::end(labels), predicate(5 * CHUNK_ELEMENTS));
		REQUIRE(it->func == "aa"); // function name is "aa" (call aa2)
		REQUIRE(chunks[0].begin[5 + (6 * CHUNK_ELEMENTS)] == it->label); // bb (call bb3) has parent "aa" (call aa2)
	}

	{
		auto it = std::find_if(std::begin(labels), std::end(labels), predicate(6 * CHUNK_ELEMENTS));
		REQUIRE(it->func == "bb"); // function name is "bb" (call bb3)
	}

	// for(std::vector<int>::size_type j = 0; j != chunks.size(); j++)
	// {
	// 	auto *c = chunks[j].begin;
	// 	for(int i = 0; i < CHUNK_SIZE; i+=CHUNK_ELEMENTS)
	// 	{
	// 		if (c[i] == 0) {
	// 			break;
	// 		}
	// 		auto parent = c[i+5];
	// 		auto e = ((unsigned long long)c[i+4])|(((unsigned long long)c[i+3])<<32);
	// 		auto s = ((unsigned long long)c[i+2])|(((unsigned long long)c[i+1])<<32);
	// 		char b[1024];
	// 		if (parent == 0) {
	// 			sprintf(b, "%u %lld", c[i], e-s);
	// 		} else {
	// 			sprintf(b, "%u;%u %lld", parent, c[i], e-s);
	// 		}
	// 		std::cout << std::string(b) << std::endl;
	// 		// char b2[1024];
	// 		// sprintf(b2, "%ld - %03d: %u", j, i, c[i]);
	// 		// std::cout << std::string(b2) << std::endl;
	// 	}
	// }

	labels.clear();
	chunks.clear();
	REQUIRE(labels.empty());
	REQUIRE(chunks.empty());
}

// TEST_CASE("ccc", "[profiler]")
// {
// 	alloc_chunk();
// 	REQUIRE(chunks.size() == 1);

// 	size_t expected_chunks = 2;
// 	int how_many_times = (CHUNK_SIZE / CHUNK_ELEMENTS) * HEDLEY_STATIC_CAST(int, expected_chunks);

// 	// Use lt (<) to avoid pre-allocation of a new chunk at last element of previous chunk
// 	for(int i = 1; i < how_many_times; i++)
// 	{
// 		profile_empty_func();
// 	}

// 	REQUIRE(labels.size() == 1);
// 	REQUIRE(chunks.size() == expected_chunks);

// 	labels.clear();
// 	chunks.clear();
// 	REQUIRE(labels.empty());
// 	REQUIRE(chunks.empty());
// }