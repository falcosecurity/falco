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

#include "ruleset.h"
#include "falco_utils.h"
#include <catch.hpp>

static bool EXACT_MATCH = true;
static bool SUBSTRING_MATCH = false;
static bool ENABLED = true;
static bool DISABLED = false;
static uint16_t DEFAULT_RULESET = 0;
static uint16_t NON_DEFAULT_RULESET = 3;
static uint16_t OTHER_NON_DEFAULT_RULESET = 2;
static std::set<std::string> TAGS = {"some_tag", "some_other_tag"};
static std::set<uint32_t> EVENT_TAGS = {1};

TEST_CASE("Ruleset", "[rulesets]")
{
	falco_ruleset r;
	auto filter = std::make_unique<gen_event_filter>();
	r.add("one_rule", TAGS, EVENT_TAGS, std::move(filter));

	SECTION("Should enable/disable for exact match w/ default ruleset")
	{
		r.enable("one_rule", EXACT_MATCH, ENABLED);
		REQUIRE(r.num_rules_for_ruleset() == 1);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 1);

		r.enable("one_rule", EXACT_MATCH, DISABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
	}

	SECTION("Should enable/disable for exact match w/ specific ruleset")
	{
		r.enable("one_rule", EXACT_MATCH, ENABLED, NON_DEFAULT_RULESET);
		REQUIRE(r.num_rules_for_ruleset(NON_DEFAULT_RULESET) == 1);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
		REQUIRE(r.num_rules_for_ruleset(OTHER_NON_DEFAULT_RULESET) == 0);

		r.enable("one_rule", EXACT_MATCH, DISABLED, NON_DEFAULT_RULESET);
		REQUIRE(r.num_rules_for_ruleset(NON_DEFAULT_RULESET) == 0);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
		REQUIRE(r.num_rules_for_ruleset(OTHER_NON_DEFAULT_RULESET) == 0);
	}

	SECTION("Should not enable for exact match different rule name")
	{
		r.enable("some_other_rule", EXACT_MATCH, ENABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
	}

	SECTION("Should enable/disable for exact match w/ substring and default ruleset")
	{
		r.enable("one_rule", SUBSTRING_MATCH, ENABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 1);

		r.enable("one_rule", SUBSTRING_MATCH, DISABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
	}

	SECTION("Should not enable for substring w/ exact_match")
	{
		r.enable("one_", EXACT_MATCH, ENABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
	}

	SECTION("Should enable/disable for prefix match w/ default ruleset", "[rulesets]")
	{
		r.enable("one_", SUBSTRING_MATCH, ENABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 1);

		r.enable("one_", SUBSTRING_MATCH, DISABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
	}

	SECTION("Should enable/disable for suffix match w/ default ruleset")
	{
		r.enable("_rule", SUBSTRING_MATCH, ENABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 1);

		r.enable("_rule", SUBSTRING_MATCH, DISABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
	}

	SECTION("Should enable/disable for substring match w/ default ruleset")
	{
		r.enable("ne_ru", SUBSTRING_MATCH, ENABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 1);

		r.enable("ne_ru", SUBSTRING_MATCH, DISABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
	}

	SECTION("Should enable/disable for substring match w/ specific ruleset")
	{
		r.enable("ne_ru", SUBSTRING_MATCH, ENABLED, NON_DEFAULT_RULESET);
		REQUIRE(r.num_rules_for_ruleset(NON_DEFAULT_RULESET) == 1);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
		REQUIRE(r.num_rules_for_ruleset(OTHER_NON_DEFAULT_RULESET) == 0);

		r.enable("ne_ru", SUBSTRING_MATCH, DISABLED, NON_DEFAULT_RULESET);
		REQUIRE(r.num_rules_for_ruleset(NON_DEFAULT_RULESET) == 0);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
		REQUIRE(r.num_rules_for_ruleset(OTHER_NON_DEFAULT_RULESET) == 0);
	}

	SECTION("Should enable/disable for tags w/ default ruleset")
	{
		std::set<std::string> want_tags = {"some_tag"};
		r.enable_tags(want_tags, ENABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 1);

		r.enable_tags(want_tags, DISABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
	}

	SECTION("Should enable/disable for tags w/ specific ruleset")
	{
		std::set<std::string> want_tags = {"some_tag"};

		r.enable_tags(want_tags, ENABLED, NON_DEFAULT_RULESET);
		REQUIRE(r.num_rules_for_ruleset(NON_DEFAULT_RULESET) == 1);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
		REQUIRE(r.num_rules_for_ruleset(OTHER_NON_DEFAULT_RULESET) == 0);

		r.enable_tags(want_tags, DISABLED, NON_DEFAULT_RULESET);
		REQUIRE(r.num_rules_for_ruleset(NON_DEFAULT_RULESET) == 0);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
		REQUIRE(r.num_rules_for_ruleset(OTHER_NON_DEFAULT_RULESET) == 0);
	}

	SECTION("Should not enable for different tags")
	{
		std::set<std::string> want_tags = {"some_different_tag"};

		r.enable_tags(want_tags, ENABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
	}

	SECTION("Should enable/disable for overlapping tags")
	{
		std::set<std::string> want_tags = {"some_tag", "some_different_tag"};

		r.enable_tags(want_tags, ENABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 1);

		r.enable_tags(want_tags, DISABLED);
		REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
	}
}

TEST_CASE("Should enable/disable for incremental adding tags", "[rulesets]")
{
	falco_ruleset r;
	auto rule1_filter = std::make_unique<gen_event_filter>();
	string rule1_name = "one_rule";
	std::set<std::string> rule1_tags = {"rule1_tag"};
	r.add(rule1_name, rule1_tags, EVENT_TAGS, std::move(rule1_filter));

	auto rule2_filter = std::make_unique<gen_event_filter>();
	string rule2_name = "two_rule";
	std::set<std::string> rule2_tags = {"rule2_tag"};
	r.add(rule2_name, rule2_tags, EVENT_TAGS, std::move(rule2_filter));

	std::set<std::string> want_tags;

	want_tags = rule1_tags;
	r.enable_tags(want_tags, ENABLED);
	REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 1);

	want_tags = rule2_tags;
	r.enable_tags(want_tags, ENABLED);
	REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 2);

	r.enable_tags(want_tags, DISABLED);
	REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 1);

	want_tags = rule1_tags;
	r.enable_tags(want_tags, DISABLED);
	REQUIRE(r.num_rules_for_ruleset(DEFAULT_RULESET) == 0);
}
