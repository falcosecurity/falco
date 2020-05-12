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

#include <flatbuffers/flatbuffers.h>
#include "profile_generated.h"

// void profile_recurse(int times)
// {
// 	PROFILEME();
// 	for(int i = 1; i < times; i++)
// 	{
// 		profile_recurse(1);
// 	}
// }

void profiler_sleep_1sec()
{
	PROFILEME();
	std::this_thread::sleep_for(std::chrono::seconds(1));
}

void profiler_sleep_2sec()
{
	PROFILEME();
	profiler_sleep_1sec();
	std::this_thread::sleep_for(std::chrono::seconds(1));
}

TEST_CASE("profiler stores labels and chunks", "[profiler]")
{
	SECTION("profiler needs to be allocated before usage")
	{
		profiler::alloc_chunk();
		REQUIRE(profiler::chunks.size() == 1);
		REQUIRE(profiler::labels.empty());
	}

	SECTION("calling a profiled function results in labels and chunks increase")
	{
		profiler_sleep_1sec();
		REQUIRE(profiler::labels.size() == 1);
		REQUIRE(profiler::chunks.size() == 1);
	}

	SECTION("calling just another profiled function that calls the one previously called should only increase labels by one")
	{
		profiler_sleep_2sec();
		REQUIRE(profiler::labels.size() == 2);
		REQUIRE(profiler::chunks.size() == 1);
	}

	SECTION("clean")
	{
		profiler::labels.clear();
		profiler::chunks.clear();
		REQUIRE(profiler::labels.empty());
		REQUIRE(profiler::chunks.empty());
	}
}

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

TEST_CASE("profiler computes parents (single chunk)", "[profiler]")
{
	profiler::alloc_chunk();
	profiler_fake_root_func();

	REQUIRE(profiler::labels.size() == 4);
	REQUIRE(profiler::chunks.size() == 1);
	REQUIRE(profiler::chunks[0].begin[5] == 0); // profiler_fake_root_func is root (parent = 0)

	auto predicate = [](int x) {
		return [=](const profiler::label &l) {
			return l.label == profiler::chunks[0].begin[x];
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

	auto root = std::find_if(std::begin(profiler::labels), std::end(profiler::labels), predicate(0));
	REQUIRE(root->func == "profiler_fake_root_func");		       // function name is "profiler_fake_root_func"
	REQUIRE(profiler::chunks[0].begin[5 + CHUNK_ELEMENTS] == root->label); // aa (call aa1) has parent "profiler_fake_root_func"

	{
		auto it = std::find_if(std::begin(profiler::labels), std::end(profiler::labels), predicate(CHUNK_ELEMENTS));
		REQUIRE(it->func == "aa");						   // function name is "aa" (call aa1)
		REQUIRE(profiler::chunks[0].begin[5 + (2 * CHUNK_ELEMENTS)] == it->label); // bb (call bb1) has parent "aa" (call aa1)
	}

	{
		auto it = std::find_if(std::begin(profiler::labels), std::end(profiler::labels), predicate(2 * CHUNK_ELEMENTS));
		REQUIRE(it->func == "bb");						     // function name is "bb" (call bb1)
		REQUIRE(profiler::chunks[0].begin[5 + (3 * CHUNK_ELEMENTS)] == root->label); // bb (call bb2) has parent "profiler_fake_root_func"
	}

	{
		auto it = std::find_if(std::begin(profiler::labels), std::end(profiler::labels), predicate(3 * CHUNK_ELEMENTS));
		REQUIRE(it->func == "bb");						     // function name is "bb" (call bb2)
		REQUIRE(profiler::chunks[0].begin[5 + (4 * CHUNK_ELEMENTS)] == root->label); // cc (call cc1) has parent "profiler_fake_root_func"
	}

	{
		auto it = std::find_if(std::begin(profiler::labels), std::end(profiler::labels), predicate(4 * CHUNK_ELEMENTS));
		REQUIRE(it->func == "cc");						     // function name is "cc" (call cc1)
		REQUIRE(profiler::chunks[0].begin[5 + (5 * CHUNK_ELEMENTS)] == root->label); // aa (call aa2) has parent "profiler_fake_root_func"
	}

	{
		auto it = std::find_if(std::begin(profiler::labels), std::end(profiler::labels), predicate(5 * CHUNK_ELEMENTS));
		REQUIRE(it->func == "aa");						   // function name is "aa" (call aa2)
		REQUIRE(profiler::chunks[0].begin[5 + (6 * CHUNK_ELEMENTS)] == it->label); // bb (call bb3) has parent "aa" (call aa2)
	}

	{
		auto it = std::find_if(std::begin(profiler::labels), std::end(profiler::labels), predicate(6 * CHUNK_ELEMENTS));
		REQUIRE(it->func == "bb"); // function name is "bb" (call bb3)
	}

	for(std::vector<int>::size_type j = 0; j != profiler::chunks.size(); j++)
	{
		auto *c = profiler::chunks[j].begin;
		for(int i = 0; i < CHUNK_SIZE; i += CHUNK_ELEMENTS)
		{
			if(c[i] == 0)
			{
				break;
			}
			auto parent = c[i + 5];
			auto e = ((unsigned long long)c[i + 4]) | (((unsigned long long)c[i + 3]) << 32);
			auto s = ((unsigned long long)c[i + 2]) | (((unsigned long long)c[i + 1]) << 32);
			char b[1024];
			if(i == 0)
			{
				sprintf(b, "#;idx;parent    ;function  ;clocks");
				std::cout << std::string(b) << std::endl;
			}
			sprintf(b, "%ld;%03d;%010u;%u;%lld", j, i, parent, c[i], e - s);
			std::cout << std::string(b) << std::endl;
		}
	}

	profiler::labels.clear();
	profiler::chunks.clear();
	REQUIRE(profiler::labels.empty());
	REQUIRE(profiler::chunks.empty());
}
// TEST_CASE("profile computes recursive parents (more chunks)", "[profiler]")
// {
// 	alloc_chunk();
// 	REQUIRE(chunks.size() == 1);

// 	size_t expected_chunks = 2;
// 	int how_many_times = (CHUNK_SIZE / CHUNK_ELEMENTS) * HEDLEY_STATIC_CAST(int, expected_chunks);

// 	profile_recurse(how_many_times);

// 	REQUIRE(labels.size() == 1);
// 	REQUIRE(chunks.size() == expected_chunks + 1);

// 	for(std::vector<int>::size_type j = 0; j != chunks.size(); j++)
// 	{
// 		auto *c = chunks[j].begin;
// 		for(int i = 0; i < CHUNK_SIZE; i++)
// 		{
// 			char b[1024];
// 			sprintf(b, "%ld - %03d: %u", j, i, c[i]);
// 			std::cout << std::string(b) << std::endl;
// 		}
// 	}

// 	labels.clear();
// 	chunks.clear();
// 	REQUIRE(labels.empty());
// 	REQUIRE(chunks.empty());
// }

TEST_CASE("profiler flatbuffer serialization deserialization", "[profiler]")
{
	flatbuffers::FlatBufferBuilder builder;

	auto node_one = profiler::CreateNodeDirect(
		builder,
		"do_init",
		"falco_engine.cpp",
		345,
		500);

	auto node_two_one = profiler::CreateNodeDirect(
		builder,
		"do_match2",
		"ruleset.cpp",
		690,
		100);

	std::vector<flatbuffers::Offset<profiler::Node>> third_level;
	third_level.push_back(node_two_one);

	auto node_two = profiler::CreateNodeDirect(
		builder,
		"do_match",
		"ruleset.cpp",
		678,
		250,
		&third_level);

	std::vector<flatbuffers::Offset<profiler::Node>> second_level;
	second_level.push_back(node_one);
	second_level.push_back(node_two);

	auto root = profiler::CreateNodeDirect(
		builder,
		"main",
		"falco.cpp",
		123,
		750,
		&second_level);

	profiler::FinishNodeBuffer(builder, root);

	SECTION("binary output has identifier")
	{
		REQUIRE(profiler::NodeBufferHasIdentifier(builder.GetBufferPointer()) == true);
	}

	SECTION("deserialization")
	{
		auto node = profiler::GetNode(builder.GetBufferPointer());

		REQUIRE(node->cycles() == 750);
		REQUIRE(node->line() == 123);
		REQUIRE(node->func()->str() == "main");
		REQUIRE(node->file()->str() == "falco.cpp");
		REQUIRE(node->childs() != nullptr);
		REQUIRE(node->childs()->size() == 2);
		REQUIRE(node->childs()->Get(0) == flatbuffers::GetTemporaryPointer(builder, node_one));
		REQUIRE(node->childs()->Get(1) == flatbuffers::GetTemporaryPointer(builder, node_two));

		auto expect_one = node->childs()->Get(0);
		REQUIRE(expect_one->cycles() == 500);
		REQUIRE(expect_one->line() == 345);
		REQUIRE(expect_one->func()->str() == "do_init");
		REQUIRE(expect_one->file()->str() == "falco_engine.cpp");
		REQUIRE(expect_one->childs() == nullptr);

		auto expect_two = node->childs()->Get(1);
		REQUIRE(expect_two->cycles() == 250);
		REQUIRE(expect_two->line() == 678);
		REQUIRE(expect_two->func()->str() == "do_match");
		REQUIRE(expect_two->file()->str() == "ruleset.cpp");
		REQUIRE(expect_two->childs() != nullptr);
		REQUIRE(expect_two->childs()->size() == 1);
		REQUIRE(expect_two->childs()->Get(0) == flatbuffers::GetTemporaryPointer(builder, node_two_one));

		auto expect_two_one = expect_two->childs()->Get(0);
		REQUIRE(expect_two_one->cycles() == 100);
		REQUIRE(expect_two_one->line() == 690);
		REQUIRE(expect_two_one->func()->str() == "do_match2");
		REQUIRE(expect_two_one->file()->str() == "ruleset.cpp");
		REQUIRE(expect_two_one->childs() == nullptr);
	}
}
