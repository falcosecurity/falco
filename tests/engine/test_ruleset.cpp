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

#include <catch.hpp>
#include "ruleset.h"

TEST_CASE("vectors can be sized and resized", "[vector]")
{
    auto rs = new falco_ruleset();

    SECTION("adding ...")
    {
        std::string s = "string";
        std::set<std::string> tagset = {"a", "b", "c"};
        std::set<uint32_t> evtset = {1, 2, 3};
        rs->add(s, tagset, evtset, nullptr);
    }

    // std::vector<int> v(5);

    // REQUIRE(v.size() == 5);
    // REQUIRE(v.capacity() >= 5);

    // SECTION("resizing bigger changes size and capacity")
    // {
    //     v.resize(10);

    //     REQUIRE(v.size() == 10);
    //     REQUIRE(v.capacity() >= 10);
    // }
    // SECTION("resizing smaller changes size but not capacity")
    // {
    //     v.resize(0);

    //     REQUIRE(v.size() == 0);
    //     REQUIRE(v.capacity() >= 5);
    // }
    // SECTION("reserving bigger changes capacity but not size")
    // {
    //     v.reserve(10);

    //     REQUIRE(v.size() == 5);
    //     REQUIRE(v.capacity() >= 10);
    // }
    // SECTION("reserving smaller does not change size or capacity")
    // {
    //     v.reserve(0);

    //     REQUIRE(v.size() == 5);
    //     REQUIRE(v.capacity() >= 5);
    // }
}
