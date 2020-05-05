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
#include <catch.hpp>

static bool exact_match = true;
static bool substring_match = false;
static bool enabled = true;
static bool disabled = false;
static uint16_t default_ruleset = 0;
static uint16_t non_default_ruleset = 3;
static uint16_t other_non_default_ruleset = 2;
static std::set<std::string> tags = {"some_tag", "some_other_tag"};
static std::set<uint32_t> event_tags = {1};

TEST_CASE("Should enable/disable for exact match w/ default ruleset", "[rulesets]")
{
	falco_ruleset r;
	gen_event_filter *filter = new gen_event_filter();
	string rule_name = "one_rule";

	r.add(rule_name, tags, event_tags, filter);

	r.enable("one_rule", exact_match, enabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 1);

	r.enable("one_rule", exact_match, disabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
}

TEST_CASE("Should enable/disable for exact match w/ specific ruleset", "[rulesets]")
{
	falco_ruleset r;
	gen_event_filter *filter = new gen_event_filter();
	string rule_name = "one_rule";

	r.add(rule_name, tags, event_tags, filter);

	r.enable("one_rule", exact_match, enabled, non_default_ruleset);
	REQUIRE(r.num_rules_for_ruleset(non_default_ruleset) == 1);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
	REQUIRE(r.num_rules_for_ruleset(other_non_default_ruleset) == 0);

	r.enable("one_rule", exact_match, disabled, non_default_ruleset);
	REQUIRE(r.num_rules_for_ruleset(non_default_ruleset) == 0);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
	REQUIRE(r.num_rules_for_ruleset(other_non_default_ruleset) == 0);
}

TEST_CASE("Should not enable for exact match different rule name", "[rulesets]")
{
	falco_ruleset r;
	gen_event_filter *filter = new gen_event_filter();
	string rule_name = "one_rule";

	r.add(rule_name, tags, event_tags, filter);

	r.enable("some_other_rule", exact_match, enabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
}

TEST_CASE("Should enable/disable for exact match w/ substring and default ruleset", "[rulesets]")
{
	falco_ruleset r;
	gen_event_filter *filter = new gen_event_filter();
	string rule_name = "one_rule";

	r.add(rule_name, tags, event_tags, filter);

	r.enable("one_rule", substring_match, enabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 1);

	r.enable("one_rule", substring_match, disabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
}

TEST_CASE("Should not enable for substring w/ exact_match", "[rulesets]")
{
	falco_ruleset r;
	gen_event_filter *filter = new gen_event_filter();
	string rule_name = "one_rule";

	r.add(rule_name, tags, event_tags, filter);

	r.enable("one_", exact_match, enabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
}

TEST_CASE("Should enable/disable for prefix match w/ default ruleset", "[rulesets]")
{
	falco_ruleset r;
	gen_event_filter *filter = new gen_event_filter();
	string rule_name = "one_rule";

	r.add(rule_name, tags, event_tags, filter);

	r.enable("one_", substring_match, enabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 1);

	r.enable("one_", substring_match, disabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
}

TEST_CASE("Should enable/disable for suffix match w/ default ruleset", "[rulesets]")
{
	falco_ruleset r;
	gen_event_filter *filter = new gen_event_filter();
	string rule_name = "one_rule";

	r.add(rule_name, tags, event_tags, filter);

	r.enable("_rule", substring_match, enabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 1);

	r.enable("_rule", substring_match, disabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
}

TEST_CASE("Should enable/disable for substring match w/ default ruleset", "[rulesets]")
{
	falco_ruleset r;
	gen_event_filter *filter = new gen_event_filter();
	string rule_name = "one_rule";

	r.add(rule_name, tags, event_tags, filter);

	r.enable("ne_ru", substring_match, enabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 1);

	r.enable("ne_ru", substring_match, disabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
}

TEST_CASE("Should enable/disable for substring match w/ specific ruleset", "[rulesets]")
{
	falco_ruleset r;
	gen_event_filter *filter = new gen_event_filter();
	string rule_name = "one_rule";

	r.add(rule_name, tags, event_tags, filter);

	r.enable("ne_ru", substring_match, enabled, non_default_ruleset);
	REQUIRE(r.num_rules_for_ruleset(non_default_ruleset) == 1);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
	REQUIRE(r.num_rules_for_ruleset(other_non_default_ruleset) == 0);

	r.enable("ne_ru", substring_match, disabled, non_default_ruleset);
	REQUIRE(r.num_rules_for_ruleset(non_default_ruleset) == 0);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
	REQUIRE(r.num_rules_for_ruleset(other_non_default_ruleset) == 0);
}

TEST_CASE("Should enable/disable for tags w/ default ruleset", "[rulesets]")
{
	falco_ruleset r;
	gen_event_filter *filter = new gen_event_filter();
	string rule_name = "one_rule";
	std::set<std::string> want_tags = {"some_tag"};

	r.add(rule_name, tags, event_tags, filter);

	r.enable_tags(want_tags, enabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 1);

	r.enable_tags(want_tags, disabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
}

TEST_CASE("Should enable/disable for tags w/ specific ruleset", "[rulesets]")
{
	falco_ruleset r;
	gen_event_filter *filter = new gen_event_filter();
	string rule_name = "one_rule";
	std::set<std::string> want_tags = {"some_tag"};

	r.add(rule_name, tags, event_tags, filter);

	r.enable_tags(want_tags, enabled, non_default_ruleset);
	REQUIRE(r.num_rules_for_ruleset(non_default_ruleset) == 1);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
	REQUIRE(r.num_rules_for_ruleset(other_non_default_ruleset) == 0);

	r.enable_tags(want_tags, disabled, non_default_ruleset);
	REQUIRE(r.num_rules_for_ruleset(non_default_ruleset) == 0);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
	REQUIRE(r.num_rules_for_ruleset(other_non_default_ruleset) == 0);
}

TEST_CASE("Should not enable for different tags", "[rulesets]")
{
	falco_ruleset r;
	gen_event_filter *filter = new gen_event_filter();
	string rule_name = "one_rule";
	std::set<std::string> want_tags = {"some_different_tag"};

	r.add(rule_name, tags, event_tags, filter);

	r.enable_tags(want_tags, enabled);
	REQUIRE(r.num_rules_for_ruleset(non_default_ruleset) == 0);
}

TEST_CASE("Should enable/disable for overlapping tags", "[rulesets]")
{
	falco_ruleset r;
	gen_event_filter *filter = new gen_event_filter();
	string rule_name = "one_rule";
	std::set<std::string> want_tags = {"some_tag", "some_different_tag"};

	r.add(rule_name, tags, event_tags, filter);

	r.enable_tags(want_tags, enabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 1);

	r.enable_tags(want_tags, disabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
}

TEST_CASE("Should enable/disable for incremental adding tags", "[rulesets]")
{
	falco_ruleset r;
	gen_event_filter *rule1_filter = new gen_event_filter();
	string rule1_name = "one_rule";
	std::set<std::string> rule1_tags = {"rule1_tag"};
	r.add(rule1_name, rule1_tags, event_tags, rule1_filter);

	gen_event_filter *rule2_filter = new gen_event_filter();
	string rule2_name = "two_rule";
	std::set<std::string> rule2_tags = {"rule2_tag"};
	r.add(rule2_name, rule2_tags, event_tags, rule2_filter);

	std::set<std::string> want_tags;

	want_tags = rule1_tags;
	r.enable_tags(want_tags, enabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 1);

	want_tags = rule2_tags;
	r.enable_tags(want_tags, enabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 2);

	r.enable_tags(want_tags, disabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 1);

	want_tags = rule1_tags;
	r.enable_tags(want_tags, disabled);
	REQUIRE(r.num_rules_for_ruleset(default_ruleset) == 0);
}
