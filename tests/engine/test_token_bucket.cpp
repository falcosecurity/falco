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

#include "token_bucket.h"
#include <catch.hpp>

using namespace Catch::literals;

TEST_CASE("token bucket ctor", "[token_bucket]")
{
}

TEST_CASE("token bucket init", "[token_bucket]")
{
    auto tb = new token_bucket();

    SECTION("at specific time")
    {
	auto max = 2.0;
	uint64_t now = 1;
	tb->init(1.0, max, now);
	REQUIRE(tb->get_last_seen() == now);
	REQUIRE(tb->get_tokens() == max);
    }

    SECTION("at current time")
    {
	// auto max = 2.0;
	// tb->init(1.0, max, 0);
	// REQUIRE(tb->get_last_seen() == );
	// REQUIRE(tb->get_tokens() == max);
    }
}

TEST_CASE("token bucket claim", "[token_bucket]")
{
    auto tb = new token_bucket();
    tb->init(2.0, 10.0, 1);

    SECTION("...")
    {
	bool claimed = tb->claim(5.0, 1000000001);
	REQUIRE(tb->get_last_seen() == 1000000001);
	REQUIRE(tb->get_tokens() == 5.0_a);
	REQUIRE(claimed);

	SECTION("xxx")
	{
	    bool claimed = tb->claim(7.0, 2000000001);
	    REQUIRE(tb->get_last_seen() == 2000000001);
	    REQUIRE(tb->get_tokens() == 0.0_a);
	    REQUIRE(claimed);

	    SECTION(";;;")
	    {
		bool claimed = tb->claim(3.0, 3000000001);
		REQUIRE(tb->get_last_seen() == 3000000001);
		REQUIRE(tb->get_tokens() == 2.0_a);
		REQUIRE_FALSE(claimed);
	    }
	}
    }
}