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

#include "falco_common.h"
#include "evttype_index_ruleset.h"
#include <filter.h>
#include <catch.hpp>

static bool exact_match = true;
static bool substring_match = false;
static uint16_t default_ruleset = 0;
static uint16_t non_default_ruleset = 3;
static uint16_t other_non_default_ruleset = 2;
static std::set<std::string> tags = {"some_tag", "some_other_tag"};
static std::set<uint16_t> evttypes = { ppm_event_type::PPME_GENERIC_E };

static std::shared_ptr<gen_event_filter_factory> create_factory()
{
	std::shared_ptr<gen_event_filter_factory> ret(new sinsp_filter_factory(NULL));

	return ret;
}

static std::shared_ptr<libsinsp::filter::ast::expr> create_ast(
	std::shared_ptr<gen_event_filter_factory> f)
{
	libsinsp::filter::parser parser("evt.type=open");
	std::shared_ptr<libsinsp::filter::ast::expr> ret(parser.parse());

	return ret;
}

static std::shared_ptr<gen_event_filter> create_filter(
	std::shared_ptr<gen_event_filter_factory> f,
	std::shared_ptr<libsinsp::filter::ast::expr> ast)
{
	sinsp_filter_compiler compiler(f, ast.get());
	std::shared_ptr<gen_event_filter> filter(compiler.compile());

	return filter;
}

static std::shared_ptr<filter_ruleset> create_ruleset(
	std::shared_ptr<gen_event_filter_factory> f)
{
	std::shared_ptr<filter_ruleset> ret(new evttype_index_ruleset(f));
	return ret;
}

TEST_CASE("Should enable/disable on ruleset", "[rulesets]")
{
	auto f = create_factory();
	auto r = create_ruleset(f);
	auto ast = create_ast(f);
	auto filter = create_filter(f, ast);
	falco_rule rule;
	rule.name = "one_rule";
	rule.source = falco_common::syscall_source;
	rule.tags = tags;

	r->add(rule, filter, ast);

	SECTION("Should enable/disable for exact match w/ default ruleset")
	{
		r->enable("one_rule", exact_match, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 1);

		r->disable("one_rule", exact_match, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
	}

	SECTION("Should enable/disable for exact match w/ specific ruleset")
	{
		r->enable("one_rule", exact_match, non_default_ruleset);
		REQUIRE(r->enabled_count(non_default_ruleset) == 1);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
		REQUIRE(r->enabled_count(other_non_default_ruleset) == 0);

		r->disable("one_rule", exact_match, non_default_ruleset);
		REQUIRE(r->enabled_count(non_default_ruleset) == 0);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
		REQUIRE(r->enabled_count(other_non_default_ruleset) == 0);
	}

	SECTION("Should not enable for exact match different rule name")
	{
		r->enable("some_other_rule", exact_match, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
	}

	SECTION("Should enable/disable for exact match w/ substring and default ruleset")
	{
		r->enable("one_rule", substring_match, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 1);

		r->disable("one_rule", substring_match, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
	}

	SECTION("Should not enable for substring w/ exact_match")
	{
		r->enable("one_", exact_match, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
	}

	SECTION("Should enable/disable for prefix match w/ default ruleset")
	{
		r->enable("one_", substring_match, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 1);

		r->disable("one_", substring_match, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
	}

	SECTION("Should enable/disable for suffix match w/ default ruleset")
	{
		r->enable("_rule", substring_match, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 1);

		r->disable("_rule", substring_match, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
	}

	SECTION("Should enable/disable for substring match w/ default ruleset")
	{
		r->enable("ne_ru", substring_match, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 1);

		r->disable("ne_ru", substring_match, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
	}

	SECTION("Should enable/disable for substring match w/ specific ruleset")
	{
		r->enable("ne_ru", substring_match, non_default_ruleset);
		REQUIRE(r->enabled_count(non_default_ruleset) == 1);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
		REQUIRE(r->enabled_count(other_non_default_ruleset) == 0);

		r->disable("ne_ru", substring_match, non_default_ruleset);
		REQUIRE(r->enabled_count(non_default_ruleset) == 0);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
		REQUIRE(r->enabled_count(other_non_default_ruleset) == 0);
	}

	SECTION("Should enable/disable for tags w/ default ruleset")
	{
		std::set<std::string> want_tags = {"some_tag"};

		r->enable_tags(want_tags, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 1);

		r->disable_tags(want_tags, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
	}

	SECTION("Should enable/disable for tags w/ specific ruleset")
	{
		std::set<std::string> want_tags = {"some_tag"};

		r->enable_tags(want_tags, non_default_ruleset);
		REQUIRE(r->enabled_count(non_default_ruleset) == 1);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
		REQUIRE(r->enabled_count(other_non_default_ruleset) == 0);

		r->disable_tags(want_tags, non_default_ruleset);
		REQUIRE(r->enabled_count(non_default_ruleset) == 0);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
		REQUIRE(r->enabled_count(other_non_default_ruleset) == 0);
	}

	SECTION("Should not enable for different tags")
	{
		std::set<std::string> want_tags = {"some_different_tag"};

		r->enable_tags(want_tags, default_ruleset);
		REQUIRE(r->enabled_count(non_default_ruleset) == 0);
	}

	SECTION("Should enable/disable for overlapping tags")
	{
		std::set<std::string> want_tags = {"some_tag", "some_different_tag"};

		r->enable_tags(want_tags, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 1);

		r->disable_tags(want_tags, default_ruleset);
		REQUIRE(r->enabled_count(default_ruleset) == 0);
	}

}

TEST_CASE("Should enable/disable on ruleset for incremental adding tags", "[rulesets]")
{
	auto f = create_factory();
	auto r = create_ruleset(f);
	auto ast = create_ast(f);

	auto rule1_filter = create_filter(f, ast);
	falco_rule rule1;
	rule1.name = "one_rule";
	rule1.source = falco_common::syscall_source;
	rule1.tags =  {"rule1_tag"};
	r->add(rule1, rule1_filter, ast);

	auto rule2_filter = create_filter(f, ast);
	falco_rule rule2;
	rule2.name = "two_rule";
	rule2.source = falco_common::syscall_source;
	rule2.tags =  {"rule2_tag"};
	r->add(rule2, rule2_filter, ast);

	std::set<std::string> want_tags;

	want_tags = rule1.tags;
	r->enable_tags(want_tags, default_ruleset);
	REQUIRE(r->enabled_count(default_ruleset) == 1);

	want_tags = rule2.tags;
	r->enable_tags(want_tags, default_ruleset);
	REQUIRE(r->enabled_count(default_ruleset) == 2);

	r->disable_tags(want_tags, default_ruleset);
	REQUIRE(r->enabled_count(default_ruleset) == 1);

	want_tags = rule1.tags;
	r->disable_tags(want_tags, default_ruleset);
	REQUIRE(r->enabled_count(default_ruleset) == 0);
}
