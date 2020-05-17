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
#include <catch.hpp>

TEST_CASE("Startswith shold match when checked string has prefix", "[utils]")
{
	bool res = falco::utils::starts_with("unix:///var/run/falco.sock", "unix://");
	REQUIRE(res);
}

TEST_CASE("Startswith shold not match when checked string does not have prefix", "[utils]")
{
	bool res = falco::utils::starts_with("unix:///var/run/falco.sock", "something://");
	REQUIRE_FALSE(res);
}

TEST_CASE("Startswith shold not match when prefix is at a random position", "[utils]")
{
	bool res = falco::utils::starts_with("/var/run/unix:///falco.sock", "unix://");
	REQUIRE_FALSE(res);
}
