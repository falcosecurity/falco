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


#include "falco_utils.h"
#include <catch.hpp>

using namespace falco::utils;
using namespace Catch::literals;

TEST_CASE("wrapping with an ident", "[wrap_test]")
{
	SECTION("empty string returns a newline")
	{
		std::string wrapped = wrap_text("", 0, 0, 0);
		const std::string &required = "\n";
		REQUIRE(wrapped == required);
	}

	SECTION("first character of string is not indented")
	{
		std::string wrapped = wrap_text("s", 0, 1, 2);
		const std::string &required = "s\n";
		REQUIRE(wrapped == required);
	}

	SECTION("2 characters per line with 1 identation")
	{
		std::string wrapped = wrap_text("falco", 0, 1, 2);
		const std::string &required =
R"(f
 a
 l
 c
 o
)";
		REQUIRE(wrapped == required);
	}

	SECTION("2 characters per line with no identation")
	{
		std::string wrapped = wrap_text("falco", 0, 0, 2);
		const std::string &required =
R"(fa
lc
o
)";
		REQUIRE(wrapped == required);
	}

/*
Perhaps use https://github.com/catchorg/Catch2/issues/553#issuecomment-164483727
to capture SIGFPE
	SECTION("mod by zero when ident 1 space with 1 character per line")
	{
		REQUIRE_THROWS(wrap_text(str, 0, 1, 1));
	}

	SECTION("any time indent == line_len SIGFPE")
	{
		REQUIRE_THROWS(wrap_text("any string", 0, 1, 1));
	}
*/
}
