/*
Copyright (C) 2019 The Falco Authors.

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

#include <memory>

#include "token_bucket.h"
#include <catch.hpp>

using namespace Catch::literals;

TEST_CASE("token bucket default ctor", "[token_bucket]")
{
	auto tb = std::make_shared<raw_token_bucket>();

	REQUIRE(tb->get_tokens() == 1);

	SECTION("initialising with specific time, rate 2 tokens/sec")
	{
		auto max = 2.0;
		uint64_t now = 1;
		tb->init(1.0, max, now);
		REQUIRE(tb->get_last_seen() == now);
		REQUIRE(tb->get_tokens() == max);
	}
}

TEST_CASE("token bucket default initialization", "[token_bucket]")
{
	raw_token_bucket tb;
	REQUIRE(tb.get_tokens() == 1);
}

TEST_CASE("token bucket ctor with custom timer", "[token_bucket]")
{
	auto t = []() -> uint64_t { return 22; };
	auto tb = std::make_shared<token_bucket>(1, 1, t);

	REQUIRE(tb->get_tokens() == 1);
	REQUIRE(tb->get_last_seen() == 22);
}

TEST_CASE("token bucket with 2 tokens/sec rate, max 10 tokens", "[token_bucket]")
{
	uint64_t time_seq[] = {1, 1000000001, 2000000001, 3000000001};
	size_t idx{0};
	std::function<uint64_t()> mock_get_time_ns = [&idx, time_seq] {
		return time_seq[(idx++) % sizeof(time_seq)];
	};
	auto tb = std::make_shared<token_bucket>(2.0, 10, mock_get_time_ns);

	SECTION("claiming 5 tokens")
	{
		bool claimed = tb->claim(5);
		REQUIRE(tb->get_last_seen() == 1000000001);
		REQUIRE(tb->get_tokens() == 5.0_a);
		REQUIRE(claimed);

		SECTION("claiming all the 7 remaining tokens")
		{
			bool claimed = tb->claim(7);
			REQUIRE(tb->get_last_seen() == 2000000001);
			REQUIRE(tb->get_tokens() == 0.0_a);
			REQUIRE(claimed);

			SECTION("claiming 1 token more than the 2 available fails")
			{
				bool claimed = tb->claim(3);
				REQUIRE(tb->get_last_seen() == 3000000001);
				REQUIRE(tb->get_tokens() == 2.0_a);
				REQUIRE_FALSE(claimed);
			}
		}
	}
}
