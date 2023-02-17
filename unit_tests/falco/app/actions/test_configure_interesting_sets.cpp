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

#include "falco_utils.h"
#include "evttype_index_ruleset.h"
#include <filter/parser.h>
#include <gtest/gtest.h>

using namespace std;
using namespace libsinsp::filter;
using namespace falco::utils;

// todo(jasondellaluce): these tests do not test the actual
// `configure_interesting_sets` action, but instead reproduces its logic
// and asserts the pre and post conditions. For now, this is the only thing
// we can do due to the falco_engine class lacking adequate accessor methods.
// In the future, we need to refactor this.

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

static std::shared_ptr<filter_ruleset> get_test_rulesets(const std::unordered_set<std::string>& fltstrs)
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

static libsinsp::events::set<ppm_event_code> extract_rules_event_set(std::shared_ptr<filter_ruleset>& r)
{
	std::set<uint16_t> tmp;
	libsinsp::events::set<ppm_event_code> events;
	auto source = falco_common::syscall_source;
	r->enabled_evttypes(tmp, 0);
	for (const auto &ev : tmp)
	{
		events.insert((ppm_event_code) ev);
	}
	return events;
}

#define ASSERT_NAMES_EQ(a, b) { \
	ASSERT_EQ(std::set<std::string>(a.begin(), a.end()), std::set<std::string>(b.begin(), b.end())); \
}

TEST(ConfigureInterestingSets, configure_interesting_sets)
{
	/* Test scenario:
	* Include one I/O syscall
	* Include one non syscall event type
	* Include one exclusionary syscall definition test ruleset
	* Check sinsp enforced syscalls dependencies for:
	*  - spawned processes
	*  - network related syscalls
	* Check that non syscalls events are enforced */
	std::unordered_set<std::string> fltstrs = {
		"(evt.type=connect or evt.type=accept)",
		"evt.type in (open, ptrace, mmap, execve, read, container)",
		"evt.type in (open, execve, mprotect) and not evt.type=mprotect"};
	std::unordered_set<std::string> expected_syscalls_names = {
		"connect", "accept", "open", "ptrace", "mmap", "execve", "read", "container"};
	std::unordered_set<std::string> base_syscalls_sinsp_state_spawned_process = {"clone", "clone3", "fork", "vfork"};
	std::unordered_set<std::string> base_syscalls_sinsp_state_network = {"socket", "bind", "close"};
	std::unordered_set<std::string> base_events = {"procexit", "container"};

	auto r = get_test_rulesets(fltstrs);
	ASSERT_EQ(r->enabled_count(0), fltstrs.size());

	/* Test if event types names were extracted from each rule in test ruleset. */
	auto rules_event_set = extract_rules_event_set(r);
	auto rules_names = libsinsp::events::event_set_to_names(rules_event_set);
	ASSERT_NAMES_EQ(rules_names, expected_syscalls_names);

	/* Enforce sinsp state syscalls and test if ruleset syscalls are in final set of syscalls. */
	auto base_event_set = libsinsp::events::sinsp_state_event_set();
	auto selected_event_set = base_event_set.merge(rules_event_set);
	auto selected_names = libsinsp::events::event_set_to_names(selected_event_set);
	auto intersection = unordered_set_intersection(selected_names, expected_syscalls_names);
	ASSERT_NAMES_EQ(intersection, expected_syscalls_names);

	/* Test if sinsp state enforcement activated required syscalls for test ruleset. */
	intersection = unordered_set_intersection(selected_names, base_syscalls_sinsp_state_spawned_process);
	ASSERT_NAMES_EQ(intersection, base_syscalls_sinsp_state_spawned_process);
	intersection = unordered_set_intersection(selected_names, base_syscalls_sinsp_state_network);
	ASSERT_NAMES_EQ(intersection, base_syscalls_sinsp_state_network);

	/* Test that no I/O syscalls are in the final set. */
	auto io_event_set = libsinsp::events::sc_set_to_event_set(libsinsp::events::io_sc_set());
	auto erased_event_set = selected_event_set.intersect(io_event_set);
	selected_event_set = selected_event_set.diff(io_event_set);
	selected_names = libsinsp::events::event_set_to_names(selected_event_set);
	intersection = unordered_set_intersection(selected_names, libsinsp::events::event_set_to_names(erased_event_set));
	ASSERT_EQ(intersection.size(), 0);

	/* Test that enforced non syscalls events are in final events set. */
	intersection = unordered_set_intersection(selected_names, base_events);
	ASSERT_NAMES_EQ(intersection, base_events);

}
