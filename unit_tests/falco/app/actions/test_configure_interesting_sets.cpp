/*
Copyright (C) 2023 The Falco Authors.

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

#include "evttype_index_ruleset.h"
#include <filter/parser.h>
#include <gtest/gtest.h>

using namespace std;
using namespace libsinsp::filter;

static std::shared_ptr<gen_event_filter_factory> create_factory()
{
	std::shared_ptr<gen_event_filter_factory> ret(new sinsp_filter_factory(NULL));
	return ret;
}

static std::shared_ptr<libsinsp::filter::ast::expr> create_ast(
	std::shared_ptr<gen_event_filter_factory> f, std::string fltstr)
{
	libsinsp::filter::parser parser(fltstr);
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

static std::shared_ptr<filter_ruleset> get_test_rulesets(std::unordered_set<std::string> fltstrs)
{
    auto f = create_factory();
    auto r = create_ruleset(f);
	
	for (const auto &fltstr : fltstrs)
	{
        auto rule_ast = create_ast(f, fltstr);
        auto rule_filter = create_filter(f, rule_ast);
        falco_rule rule;
        rule.name = fltstr;
        rule.source = falco_common::syscall_source;
        r->add(rule, rule_filter, rule_ast);
		r->enable(fltstr, true, 0);
    }
    return r;
}

template<typename T>
std::set<T> unordered_set_to_ordered(std::unordered_set<T> unordered_set)
{
	std::set<T> s;
	for(const auto& val : unordered_set)
	{
		s.insert(val);
	}
	return s;
}
template std::set<std::string> unordered_set_to_ordered(std::unordered_set<std::string> unordered_set);

void compare_evttypes_names(std::unordered_set<std::string> &actual, std::unordered_set<std::string> &expected)
{
	ASSERT_EQ(actual.size(), expected.size());
	std::set<std::string> actual_sorted = unordered_set_to_ordered(actual);
	std::set<std::string> expected_sorted = unordered_set_to_ordered(expected);

	auto final = actual_sorted.begin();
	auto matching = expected_sorted.begin();

	for(; final != actual_sorted.end(); final++, matching++)
	{
		ASSERT_TRUE(*matching == *final);
	}
}

std::unordered_set<std::string> extract_rules_event_names(std::unique_ptr<sinsp>& inspector, std::shared_ptr<filter_ruleset> r)
{
	std::set<uint16_t> rule_events;
	r->enabled_evttypes(rule_events, 0);
	std::unordered_set<uint32_t> ppme_events_codes(rule_events.begin(), rule_events.end());
	return inspector->get_events_names(ppme_events_codes);
}

std::unordered_set<uint32_t> get_syscalls_ppm_codes(const std::unordered_set<std::string> syscalls_names)
{
	std::unordered_set<uint32_t> ppm_sc_set = {};
	for (int ppm_sc_code = 0; ppm_sc_code < PPM_SC_MAX; ++ppm_sc_code)
	{
		std::string ppm_sc_name = g_infotables.m_syscall_info_table[ppm_sc_code].name;
		if (syscalls_names.find(ppm_sc_name) != syscalls_names.end())
		{
			ppm_sc_set.insert(ppm_sc_code);
		}
	}
	return ppm_sc_set;
}

void compare_syscalls_subset_names(std::unordered_set<std::string> &total_enforced, std::unordered_set<std::string> &subset, bool inverted = false)
{
	ASSERT_GE(total_enforced.size(), subset.size());
	/* Check if each item in subset is in the total_enforced set. */
	unsigned long int counter = 0;
	for (const auto &ppm_sc_name : subset)
	{
		if (total_enforced.find(ppm_sc_name) != total_enforced.end())
		{
			counter++;
		}
	}
	if (inverted)
	{
		ASSERT_EQ(0, counter);
	} else
	{
		ASSERT_EQ(subset.size(), counter);	
	}
}

std::unordered_set<std::string> erase_io_syscalls(std::unordered_set<uint32_t> &ppm_sc_of_interest)
{
	std::unordered_set<std::string> erased_io_syscalls_names = {};
	std::unordered_set<uint32_t> cur_ppm_sc_set = ppm_sc_of_interest;
	const int bitmask = EC_SYSCALL - 1;
	for (const auto &ppm_sc_code : cur_ppm_sc_set)
	{
		switch(g_infotables.m_syscall_info_table[ppm_sc_code].category & bitmask)
		{
		case EC_IO_READ:
		case EC_IO_WRITE:
			ppm_sc_of_interest.erase(ppm_sc_code);
			erased_io_syscalls_names.insert(g_infotables.m_syscall_info_table[ppm_sc_code].name);
		}
	}
	return erased_io_syscalls_names;
}

TEST(ConfigureInterestingSets, configure_interesting_sets)
{

	std::unique_ptr<sinsp> inspector(new sinsp());

	/* Test scenario:
	*
	* Include one I/O syscall
	* Include one non syscall event type
	* Include one exclusionary syscall definition test ruleset
	* Check sinsp enforced syscalls dependencies for:
	*  - spawned processes
	*  - network related syscalls
	*/
	std::unordered_set<std::string> fltstrs = {
		"(evt.type=connect or evt.type=accept)",
		"evt.type in (open, ptrace, mmap, execve, read, container)",
		"evt.type in (open, execve, mprotect) and not evt.type=mprotect"};
	std::string test_io_syscall = "read";
	std::string test_non_syscall = "container";
	std::unordered_set<std::string> expected_syscalls_names = {
		"connect", "accept", "open", "ptrace", "mmap", "execve"};
	expected_syscalls_names.insert(test_io_syscall);
	std::unordered_set<std::string> expected_evttypes_names = expected_syscalls_names;
	expected_evttypes_names.insert(test_non_syscall);
	std::unordered_set<std::string> base_syscalls_sinsp_state_spawned_process = {"clone", "clone3", "fork", "vfork"};
	std::unordered_set<std::string> base_syscalls_sinsp_state_network = {"socket", "bind", "close"};

	auto r = get_test_rulesets(fltstrs);
	ASSERT_EQ(r->enabled_count(0), fltstrs.size());

	/* Test if event types names were extracted from each rule in test ruleset. */
	std::unordered_set<std::string> rules_evttypes_names = extract_rules_event_names(inspector, r);
	compare_evttypes_names(rules_evttypes_names, expected_evttypes_names);

	/* Same test again for syscalls events. */
	std::unordered_set<uint32_t> rules_ppm_sc_set = get_syscalls_ppm_codes(rules_evttypes_names);
	std::unordered_set<std::string> rules_syscalls_names = inspector->get_syscalls_names(rules_ppm_sc_set);
	compare_evttypes_names(rules_syscalls_names, expected_syscalls_names);

	/* Enforce sinsp state syscalls and test if ruleset syscalls are in final set of syscalls. */
	std::unordered_set<uint32_t> ppm_sc_of_interest = inspector->enforce_simple_ppm_sc_set(rules_ppm_sc_set);
	std::unordered_set<std::string> rules_syscalls_names_enforced = inspector->get_syscalls_names(ppm_sc_of_interest);
	compare_syscalls_subset_names(rules_syscalls_names_enforced, expected_syscalls_names);

	/* Test if sinsp state enforcement activated required syscalls for test ruleset. */
	compare_syscalls_subset_names(rules_syscalls_names_enforced, base_syscalls_sinsp_state_spawned_process);
	compare_syscalls_subset_names(rules_syscalls_names_enforced, base_syscalls_sinsp_state_network);

	/* Test that no I/O syscalls are in the final set. */
	std::unordered_set<std::string> erased_io_syscalls_names = erase_io_syscalls(ppm_sc_of_interest);
	rules_syscalls_names_enforced = inspector->get_syscalls_names(ppm_sc_of_interest);
	compare_syscalls_subset_names(rules_syscalls_names_enforced, erased_io_syscalls_names, true);
}
