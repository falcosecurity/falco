/*
Copyright (C) 2022 The Falco Authors.

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

#include "app_action_manager.h"

#include <algorithm>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include <catch.hpp>

// Test actions just record the order they were run (or skipped)
class test_action : public falco::app::runnable_action {
public:

	static std::vector<std::string> s_actions_run;

	test_action(const std::string &name,
		    const std::string &group,
		    const std::list<std::string> &prerequsites,
		    run_result res)
		: m_name(name),
		  m_group(group),
		  m_prerequsites(prerequsites),
		  m_res(res)
		{
		}

	~test_action()
		{
		}

	const std::string &name()
	{
		return m_name;
	}

	const std::string &group()
	{
		return m_group;
	}

	const std::list<std::string> &prerequsites()
	{
		return m_prerequsites;
	}

	run_result run()
	{
		s_actions_run.push_back(m_name);
		return m_res;
	}

private:
	std::string m_name;
	std::string m_group;
	std::list<std::string> m_prerequsites;
	run_result m_res;
};

std::vector<std::string> test_action::s_actions_run;

static std::list<std::string> empty;
static std::list<std::string> prereq_a = {"a"};
static std::list<std::string> prereq_aa = {"aa"};
static std::list<std::string> prereq_ab = {"ab"};
static std::list<std::string> prereq_m = {"m"};
static std::list<std::string> prereq_n = {"n"};

// The action names denote the dependency order e.g. "a", "b", "c" are
// all independent, "aa" and "ab" depend on a but are independent of
// each other, "aaa" "aab" depend on "aa" but are independent, etc.

static falco::app::runnable_action::run_result success_proceed{true, "", true};

static falco::app::runnable_action::run_result success_noproceed{true, "", false};


static std::shared_ptr<test_action> a = std::make_shared<test_action>(std::string("a"),
								      std::string("init"),
								      empty,
								      success_proceed);

static std::shared_ptr<test_action> a_noproceed = std::make_shared<test_action>(std::string("a"),
										std::string("init"),
										empty,
										success_noproceed);

static std::shared_ptr<test_action> b = std::make_shared<test_action>(std::string("b"),
								      std::string("init"),
								      empty,
								      success_proceed);

static std::shared_ptr<test_action> c = std::make_shared<test_action>(std::string("c"),
								      std::string("init"),
								      empty,
								      success_proceed);

static std::shared_ptr<test_action> d = std::make_shared<test_action>(std::string("d"),
								      std::string("init"),
								      empty,
								      success_proceed);

std::shared_ptr<test_action> aa = std::make_shared<test_action>(std::string("aa"),
								std::string("init"),
								prereq_a,
								success_proceed);

std::shared_ptr<test_action> ab = std::make_shared<test_action>(std::string("ab"),
								std::string("init"),
								prereq_a,
								success_proceed);

std::shared_ptr<test_action> aa_noproceed = std::make_shared<test_action>(std::string("aa"),
									  std::string("init"),
									  prereq_a,
									  success_noproceed);

std::shared_ptr<test_action> aaa = std::make_shared<test_action>(std::string("aaa"),
								 std::string("init"),
								 prereq_aa,
								 success_proceed);

std::shared_ptr<test_action> aab = std::make_shared<test_action>(std::string("aab"),
								 std::string("init"),
								 prereq_aa,
								 success_proceed);

std::shared_ptr<test_action> aba = std::make_shared<test_action>(std::string("aba"),
								 std::string("init"),
								 prereq_ab,
								 success_proceed);

static std::shared_ptr<test_action> m = std::make_shared<test_action>(std::string("m"),
								      std::string("run"),
								      empty,
								      success_proceed);

static std::shared_ptr<test_action> ma = std::make_shared<test_action>(std::string("ma"),
								       std::string("run"),
								       prereq_m,
								       success_proceed);

static std::shared_ptr<test_action> n = std::make_shared<test_action>(std::string("n"),
								      std::string("run"),
								      empty,
								      success_proceed);

static std::shared_ptr<test_action> na = std::make_shared<test_action>(std::string("na"),
								       std::string("run"),
								       prereq_n,
								       success_proceed);

static std::vector<std::string>::iterator find_action(const std::string &name,
						      std::vector<std::string>::iterator begin = test_action::s_actions_run.begin())
{
	return std::find(begin,
			 test_action::s_actions_run.end(),
			 name);
}

static bool action_is_found(const std::string &name,
			    std::vector<std::string>::iterator begin = test_action::s_actions_run.begin())
{
	auto it = find_action(name, begin);

	return (it != test_action::s_actions_run.end());
}

TEST_CASE("action manager can add and run actions", "[actions]")
{
	std::list<std::string> groups = {"init", "run"};

	SECTION("Two independent")
	{
		falco::app::action_manager amgr;
		amgr.set_groups(groups);

		test_action::s_actions_run.clear();

		amgr.add(a);
		amgr.add(b);

		amgr.run();

		// Can't compare to any direct vector as order is not guaranteed
		REQUIRE(action_is_found(a->name()) == true);
		REQUIRE(action_is_found(b->name()) == true);
	}

	SECTION("Two dependent")
	{
		falco::app::action_manager amgr;
		amgr.set_groups(groups);

		test_action::s_actions_run.clear();

		amgr.add(a);
		amgr.add(aa);

		amgr.run();

		std::vector<std::string> exp_actions_run = {"a", "aa"};
		REQUIRE(test_action::s_actions_run == exp_actions_run);
	}

	SECTION("One independent, two dependent")
	{
		falco::app::action_manager amgr;
		amgr.set_groups(groups);

		test_action::s_actions_run.clear();

		amgr.add(a);
		amgr.add(aa);
		amgr.add(b);

		amgr.run();

		// Can't compare to any direct vector as order is not guaranteed
		REQUIRE(action_is_found(a->name()) == true);
		REQUIRE(action_is_found(aa->name()) == true);
		REQUIRE(action_is_found(b->name()) == true);

		// Ensure that aa appears after a
		auto it = find_action(a->name());
		REQUIRE(action_is_found(aa->name(), it) == true);
	}

	SECTION("Two dependent, first does not proceed")
	{
		falco::app::action_manager amgr;
		amgr.set_groups(groups);

		test_action::s_actions_run.clear();

		amgr.add(a_noproceed);
		amgr.add(aa);

		amgr.run();

		std::vector<std::string> exp_actions_run = {"a"};
		REQUIRE(test_action::s_actions_run == exp_actions_run);
	}

	SECTION("Two dependent, second does not proceed")
	{
		falco::app::action_manager amgr;
		amgr.set_groups(groups);

		test_action::s_actions_run.clear();

		amgr.add(a);
		amgr.add(aa_noproceed);

		amgr.run();

		std::vector<std::string> exp_actions_run = {"a", "aa"};
		REQUIRE(test_action::s_actions_run == exp_actions_run);
	}

	SECTION("Three dependent, first does not proceed")
	{
		falco::app::action_manager amgr;
		amgr.set_groups(groups);

		test_action::s_actions_run.clear();

		amgr.add(a_noproceed);
		amgr.add(aa);
		amgr.add(aaa);

		amgr.run();

		std::vector<std::string> exp_actions_run = {"a"};
		REQUIRE(test_action::s_actions_run == exp_actions_run);
	}

	SECTION("Three dependent, second does not proceed")
	{
		falco::app::action_manager amgr;
		amgr.set_groups(groups);

		test_action::s_actions_run.clear();

		amgr.add(a);
		amgr.add(aa_noproceed);
		amgr.add(aaa);

		amgr.run();

		std::vector<std::string> exp_actions_run = {"a", "aa"};
		REQUIRE(test_action::s_actions_run == exp_actions_run);
	}

	SECTION("Groups")
	{
		falco::app::action_manager amgr;
		amgr.set_groups(groups);

		test_action::s_actions_run.clear();

		amgr.add(ma);
		amgr.add(m);
		amgr.add(aa);
		amgr.add(a);

		amgr.run();

		std::vector<std::string> exp_actions_run = {"a", "aa", "m", "ma"};
		REQUIRE(test_action::s_actions_run == exp_actions_run);
	}

	SECTION("Complex")
	{
		falco::app::action_manager amgr;
		amgr.set_groups(groups);

		test_action::s_actions_run.clear();

		amgr.add(a);
		amgr.add(b);
		amgr.add(c);
		amgr.add(d);
		amgr.add(aa);
		amgr.add(ab);
		amgr.add(aaa);
		amgr.add(aab);
		amgr.add(aba);
		amgr.add(m);
		amgr.add(ma);
		amgr.add(n);
		amgr.add(na);

		amgr.run();

		// a, b, c, d must be found. Order not specified.
		REQUIRE(action_is_found(a->name()) == true);
		REQUIRE(action_is_found(b->name()) == true);
		REQUIRE(action_is_found(c->name()) == true);
		REQUIRE(action_is_found(d->name()) == true);

		// aa, ab must be after a.
		auto it = find_action(a->name());
		REQUIRE(action_is_found(aa->name(), it) == true);
		REQUIRE(action_is_found(ab->name(), it) == true);

		// aaa, aab must be after aa
		it = find_action(aa->name());
		REQUIRE(action_is_found(aaa->name(), it) == true);
		REQUIRE(action_is_found(aab->name(), it) == true);

		// aba must be after ab
		it = find_action(ab->name());
		REQUIRE(action_is_found(aba->name(), it) == true);

		// The run actions must be the last four
		std::vector<std::string>::iterator last_four = test_action::s_actions_run.end() - 4;
		REQUIRE(action_is_found(m->name(), last_four) == true);
		REQUIRE(action_is_found(ma->name(), last_four) == true);
		REQUIRE(action_is_found(n->name(), last_four) == true);
		REQUIRE(action_is_found(na->name(), last_four) == true);

		// ma must be after m
		it = find_action(m->name());
		REQUIRE(action_is_found(ma->name(), it) == true);

		// na must be after n
		it = find_action(n->name());
		REQUIRE(action_is_found(na->name(), it) == true);
	}
}
