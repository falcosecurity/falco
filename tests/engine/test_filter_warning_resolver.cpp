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

#include "filter_warning_resolver.h"
#include <catch.hpp>

static bool warns(const std::string& condition)
{
	std::set<falco::load_result::warning_code> w;
	auto ast = libsinsp::filter::parser(condition).parse();
	filter_warning_resolver().run(ast, w);
	delete ast;
	return !w.empty();
}

TEST_CASE("Should spot warnings in filtering conditions", "[rule_loader]")
{
	SECTION("for unsafe usage of <NA> in k8s audit fields")
	{
		REQUIRE(false == warns("ka.field exists"));
		REQUIRE(false == warns("some.field = <NA>"));
		REQUIRE(true == warns("jevt.field = <NA>"));
		REQUIRE(true == warns("ka.field = <NA>"));
		REQUIRE(true == warns("ka.field == <NA>"));
		REQUIRE(true == warns("ka.field != <NA>"));
		REQUIRE(true == warns("ka.field in (<NA>)"));
		REQUIRE(true == warns("ka.field in (otherval, <NA>)"));
		REQUIRE(true == warns("ka.field intersects (<NA>)"));
		REQUIRE(true == warns("ka.field intersects (otherval, <NA>)"));
		REQUIRE(true == warns("ka.field pmatch (<NA>)"));
		REQUIRE(true == warns("ka.field pmatch (otherval, <NA>)"));
	}
}
