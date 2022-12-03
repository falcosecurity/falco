/*
Copyright (C) 2021 The Falco Authors.

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
#include "configuration.h"
#include <catch.hpp>

std::string sample_yaml = 
    "base_value:\n"
    "    id: 1\n"
    "    name: 'sample_name'\n"
    "    subvalue:\n"
    "      subvalue2:\n"
    "        boolean: true\n"
    "base_value_2:\n"
    "  sample_list:\n"
    "    - elem1\n"
    "    - elem2\n"
    "    - elem3\n"
;

TEST_CASE("configuration must load YAML data", "[configuration]")
{
    yaml_helper conf;

    SECTION("broken YAML")
    {
        std::string sample_broken_yaml = sample_yaml + " /  bad_symbol";
        REQUIRE_THROWS(conf.load_from_string(sample_broken_yaml));
    }

    SECTION("valid YAML")
    {    
        REQUIRE_NOTHROW(conf.load_from_string(sample_yaml));
    }

    SECTION("clearing and reloading")
    {   
        conf.load_from_string(sample_yaml);
        REQUIRE(conf.is_defined("base_value") == true);
        conf.clear();
        REQUIRE(conf.is_defined("base_value") == false);
        conf.load_from_string(sample_yaml);
        REQUIRE(conf.is_defined("base_value") == true);
    }
}

TEST_CASE("configuration must read YAML fields", "[configuration]")
{
	yaml_helper conf;
    conf.load_from_string(sample_yaml);

    SECTION("base level")
    {
        REQUIRE(conf.is_defined("base_value") == true);
        REQUIRE(conf.is_defined("base_value_2") == true);
        REQUIRE(conf.is_defined("unknown_base_value") == false);
    }

    SECTION("arbitrary depth nesting")
    {
        REQUIRE(conf.get_scalar<int>("base_value.id", -1) == 1);
        REQUIRE(conf.get_scalar<std::string>("base_value.name", "none") == "sample_name");
        REQUIRE(conf.get_scalar<bool>("base_value.subvalue.subvalue2.boolean", false) == true);
    }
    
    SECTION("list field elements")
    {
        REQUIRE(conf.get_scalar<std::string>("base_value_2.sample_list[0]", "none") == "elem1");
        REQUIRE(conf.get_scalar<std::string>("base_value_2.sample_list[1]", "none") == "elem2");
        REQUIRE(conf.get_scalar<std::string>("base_value_2.sample_list[2]", "none") == "elem3");
    }

    SECTION("sequence")
    {
        std::vector<std::string> seq;
        conf.get_sequence(seq, "base_value_2.sample_list");
        REQUIRE(seq.size() == 3);
        REQUIRE(seq[0] == "elem1");
        REQUIRE(seq[1] == "elem2");
        REQUIRE(seq[2] == "elem3");
    }
}

TEST_CASE("configuration must modify YAML fields", "[configuration]")
{
    std::string key = "base_value.subvalue.subvalue2.boolean";
	yaml_helper conf;
    conf.load_from_string(sample_yaml);
    REQUIRE(conf.get_scalar<bool>(key, false) == true);
    conf.set_scalar<bool>(key, false);
    REQUIRE(conf.get_scalar<bool>(key, true) == false);
    conf.set_scalar<bool>(key, true);
    REQUIRE(conf.get_scalar<bool>(key, false) == true);
}
