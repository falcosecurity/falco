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
#include "falco_utils.h"
#include <nonstd/string_view.hpp>
#include <catch.hpp>

TEST_CASE("is_unix_scheme matches", "[utils]")
{
	SECTION("rvalue")
	{
		bool res = falco::utils::network::is_unix_scheme("unix:///var/run/falco.sock");
		REQUIRE(res);
	}

	SECTION("std::string")
	{
		std::string url("unix:///var/run/falco.sock");
		bool res = falco::utils::network::is_unix_scheme(url);
		REQUIRE(res);
	}

	SECTION("char[]")
	{
		char url[] = "unix:///var/run/falco.sock";
		bool res = falco::utils::network::is_unix_scheme(url);
		REQUIRE(res);
	}
}

TEST_CASE("is_unix_scheme does not match", "[utils]")
{
	bool res = falco::utils::network::is_unix_scheme("something:///var/run/falco.sock");
	REQUIRE_FALSE(res);
}

TEST_CASE("is_unix_scheme only matches scheme at the start of the string", "[utils]")
{
	bool res = falco::utils::network::is_unix_scheme("/var/run/unix:///falco.sock");
	REQUIRE_FALSE(res);
}
