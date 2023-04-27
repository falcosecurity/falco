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

#include <falco_engine.h>

#include <falco/app/app.h>
#include <falco/app/state.h>
#include <falco/app/actions/actions.h>

#include <gtest/gtest.h>

#define ASSERT_NAMES_EQ(a, b) { \
	EXPECT_EQ(_order(a).size(), _order(b).size()); \
	ASSERT_EQ(_order(a), _order(b)); \
}

#define ASSERT_NAMES_CONTAIN(a, b) { \
	ASSERT_NAMES_EQ(unordered_set_intersection(a, b), b); \
}

#define ASSERT_NAMES_NOCONTAIN(a, b) { \
	ASSERT_NAMES_EQ(unordered_set_intersection(a, b), strset_t({})); \
}

using strset_t = std::unordered_set<std::string>;

static std::set<std::string> _order(const strset_t& s) 
{
	return std::set<std::string>(s.begin(), s.end());
}

static std::string s_sample_ruleset = "sample-ruleset";

static std::string s_sample_source = falco_common::syscall_source;

static strset_t s_sample_filters = {
	"evt.type=connect or evt.type=accept or evt.type=accept4 or evt.type=umount2",
	"evt.type in (open, ptrace, mmap, execve, read, container)",
	"evt.type in (open, execve, mprotect) and not evt.type=mprotect"};

static strset_t s_sample_generic_filters = {
	"evt.type=syncfs or evt.type=fanotify_init"};

static strset_t s_sample_nonsyscall_filters = {
	"evt.type in (procexit, switch, pluginevent, container)"};


// todo(jasondellaluce): once we have deeper and more modular
// control on the falco engine, make this a little nicer
static std::shared_ptr<falco_engine> mock_engine_from_filters(const strset_t& filters)
{
	// craft a fake ruleset with the given filters
	int n_rules = 0;
	std::string dummy_rules;
	falco::load_result::rules_contents_t content = {{"dummy_rules.yaml", dummy_rules}};
	for (const auto& f : filters)
	{
		n_rules++;
		dummy_rules +=
			"- rule: Dummy Rule " + std::to_string(n_rules) + "\n"
			+ "  output: Dummy Output " + std::to_string(n_rules) + "\n"
			+ "  condition: " + f + "\n"
			+ "  desc: Dummy Desc " + std::to_string(n_rules) + "\n"
			+ "  priority: CRITICAL\n\n";
	}

	// create a falco engine and load the ruleset
	std::shared_ptr<falco_engine> res(new falco_engine());
	auto filter_factory = std::shared_ptr<gen_event_filter_factory>(
			new sinsp_filter_factory(nullptr));
	auto formatter_factory = std::shared_ptr<gen_event_formatter_factory>(
			new sinsp_evt_formatter_factory(nullptr));
	res->add_source(s_sample_source, filter_factory, formatter_factory);
	res->load_rules(dummy_rules, "dummy_rules.yaml");
	res->enable_rule("", true, s_sample_ruleset);
	return res;
}

TEST(ConfigureInterestingSets, engine_codes_syscalls_set)
{

	auto engine = mock_engine_from_filters(s_sample_filters);
	auto enabled_count = engine->num_rules_for_ruleset(s_sample_ruleset);
	ASSERT_EQ(enabled_count, s_sample_filters.size());

	// test if event code names were extracted from each rule in test ruleset.
	auto rules_event_set = engine->event_codes_for_ruleset(s_sample_source);
	auto rules_event_names = libsinsp::events::event_set_to_names(rules_event_set);
	ASSERT_NAMES_EQ(rules_event_names, strset_t({
		"connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", "read", "container"}));

	// test if sc code names were extracted from each rule in test ruleset.
	// note, this is not supposed to contain "container", as that's an event
	// not mapped through the ppm_sc_code enumerative.
	auto rules_sc_set = engine->sc_codes_for_ruleset(s_sample_source);
	auto rules_sc_names = libsinsp::events::sc_set_to_event_names(rules_sc_set);
	ASSERT_NAMES_EQ(rules_sc_names, strset_t({
		"connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", "read"}));
}

TEST(ConfigureInterestingSets, preconditions_postconditions)
{
	auto mock_engine = mock_engine_from_filters(s_sample_filters);
	falco::app::state s1;

	s1.engine = mock_engine;
	s1.config = nullptr;
	auto result = falco::app::actions::configure_interesting_sets(s1);
	ASSERT_FALSE(result.success);
	ASSERT_NE(result.errstr, "");

	s1.engine = nullptr;
	s1.config = std::make_shared<falco_configuration>();
	result = falco::app::actions::configure_interesting_sets(s1);
	ASSERT_FALSE(result.success);
	ASSERT_NE(result.errstr, "");

	s1.engine = mock_engine;
	s1.config = std::make_shared<falco_configuration>();
	result = falco::app::actions::configure_interesting_sets(s1);
	ASSERT_TRUE(result.success);
	ASSERT_EQ(result.errstr, "");

	auto prev_selection_size = s1.selected_sc_set.size();
	result = falco::app::actions::configure_interesting_sets(s1);
	ASSERT_TRUE(result.success);
	ASSERT_EQ(result.errstr, "");
	ASSERT_EQ(prev_selection_size, s1.selected_sc_set.size());
}

TEST(ConfigureInterestingSets, engine_codes_nonsyscalls_set)
{
	auto filters = s_sample_filters;
	filters.insert(s_sample_generic_filters.begin(), s_sample_generic_filters.end());
	filters.insert(s_sample_nonsyscall_filters.begin(), s_sample_nonsyscall_filters.end());

	auto engine = mock_engine_from_filters(filters);
	auto enabled_count = engine->num_rules_for_ruleset(s_sample_ruleset);
	ASSERT_EQ(enabled_count, filters.size());

	auto rules_event_set = engine->event_codes_for_ruleset(s_sample_source);
	auto rules_event_names = libsinsp::events::event_set_to_names(rules_event_set);
	// note: including even one generic event will cause PPME_GENERIC_E to be
	// included in the ruleset's event codes. As such, when translating to names,
	// PPME_GENERIC_E will cause all names of generic events to be added!
	// This is a good example of information loss from ppm_event_code <-> ppm_sc_code.
	auto generic_names = libsinsp::events::event_set_to_names({ppm_event_code::PPME_GENERIC_E});
	auto expected_names = strset_t({
		"connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", "read", "container", // ruleset
		"procexit", "switch", "pluginevent"}); // from non-syscall event filters
	expected_names.insert(generic_names.begin(), generic_names.end());
	ASSERT_NAMES_EQ(rules_event_names, expected_names);

	auto rules_sc_set = engine->sc_codes_for_ruleset(s_sample_source);
	auto rules_sc_names = libsinsp::events::sc_set_to_event_names(rules_sc_set);
	ASSERT_NAMES_EQ(rules_sc_names, strset_t({
		"connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", "read",
		"procexit", "switch", "syncfs", "fanotify_init", // from generic event filters
	}));
}

TEST(ConfigureInterestingSets, selection_not_allevents)
{
	falco::app::state s2;
	// run app action with fake engine and without the `-A` option
	s2.engine = mock_engine_from_filters(s_sample_filters);
	s2.options.all_events = false;

	ASSERT_EQ(s2.options.all_events, false);
	auto result = falco::app::actions::configure_interesting_sets(s2);
	ASSERT_TRUE(result.success);
	ASSERT_EQ(result.errstr, "");

	// todo(jasondellaluce): once we have deeper control on falco's outputs,
	// also check if a warning has been printed in stderr

	// check that the final selected set is the one expected
	ASSERT_GT(s2.selected_sc_set.size(), 1);
	auto selected_sc_names = libsinsp::events::sc_set_to_event_names(s2.selected_sc_set);
	auto expected_sc_names = strset_t({
		// note: we expect the "read" syscall to have been erased
		"connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", // from ruleset
		"clone", "clone3", "fork", "vfork", // from sinsp state set (spawned_process)
		"socket", "bind", "close" // from sinsp state set (network, files)
	});
	ASSERT_NAMES_CONTAIN(selected_sc_names, expected_sc_names);

	// check that all IO syscalls have been erased from the selection
	auto ignored_set = falco::app::ignored_sc_set();
	auto erased_sc_names = libsinsp::events::sc_set_to_event_names(ignored_set);
	ASSERT_NAMES_NOCONTAIN(selected_sc_names, erased_sc_names);

	// check that final selected set is exactly sinsp state + ruleset
	auto rule_set = s2.engine->sc_codes_for_ruleset(s_sample_source, s_sample_ruleset);
	auto state_set = libsinsp::events::sinsp_state_sc_set();
	for (const auto &erased : ignored_set)
	{
		rule_set.remove(erased);
		state_set.remove(erased);
	}
	auto union_set = state_set.merge(rule_set);
	auto inter_set = state_set.intersect(rule_set);
	EXPECT_EQ(s2.selected_sc_set.size(), state_set.size() + rule_set.size() - inter_set.size());
	ASSERT_EQ(s2.selected_sc_set, union_set);
}

TEST(ConfigureInterestingSets, selection_allevents)
{
	falco::app::state s3;
	// run app action with fake engine and with the `-A` option
	s3.engine = mock_engine_from_filters(s_sample_filters);
	s3.options.all_events = true;
	auto result = falco::app::actions::configure_interesting_sets(s3);
	ASSERT_TRUE(result.success);
	ASSERT_EQ(result.errstr, "");

	// todo(jasondellaluce): once we have deeper control on falco's outputs,
	// also check if a warning has not been printed in stderr

	// check that the final selected set is the one expected
	ASSERT_GT(s3.selected_sc_set.size(), 1);
	auto selected_sc_names = libsinsp::events::sc_set_to_event_names(s3.selected_sc_set);
	auto expected_sc_names = strset_t({
		// note: we expect the "read" syscall to not be erased
		"connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", "read", // from ruleset
		"clone", "clone3", "fork", "vfork", // from sinsp state set (spawned_process)
		"socket", "bind", "close" // from sinsp state set (network, files)
	});
	ASSERT_NAMES_CONTAIN(selected_sc_names, expected_sc_names);

	// check that final selected set is exactly sinsp state + ruleset
	auto rule_set = s3.engine->sc_codes_for_ruleset(s_sample_source, s_sample_ruleset);
	auto state_set = libsinsp::events::sinsp_state_sc_set();
	auto union_set = state_set.merge(rule_set);
	auto inter_set = state_set.intersect(rule_set);
	EXPECT_EQ(s3.selected_sc_set.size(), state_set.size() + rule_set.size() - inter_set.size());
	ASSERT_EQ(s3.selected_sc_set, union_set);
}

TEST(ConfigureInterestingSets, selection_generic_evts)
{
	falco::app::state s4;
	// run app action with fake engine and without the `-A` option
	s4.options.all_events = false;
	auto filters = s_sample_filters;
	filters.insert(s_sample_generic_filters.begin(), s_sample_generic_filters.end());
	s4.engine = mock_engine_from_filters(filters);
	auto result = falco::app::actions::configure_interesting_sets(s4);
	ASSERT_TRUE(result.success);
	ASSERT_EQ(result.errstr, "");

	// check that the final selected set is the one expected
	ASSERT_GT(s4.selected_sc_set.size(), 1);
	auto selected_sc_names = libsinsp::events::sc_set_to_event_names(s4.selected_sc_set);
	auto expected_sc_names = strset_t({
		// note: we expect the "read" syscall to not be erased
		"connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", // from ruleset
		"syncfs", "fanotify_init",  // from ruleset (generic events)
		"clone", "clone3", "fork", "vfork", // from sinsp state set (spawned_process)
		"socket", "bind", "close" // from sinsp state set (network, files)
	});
	ASSERT_NAMES_CONTAIN(selected_sc_names, expected_sc_names);
	auto unexpected_sc_names = libsinsp::events::sc_set_to_event_names(falco::app::ignored_sc_set());
	ASSERT_NAMES_NOCONTAIN(selected_sc_names, unexpected_sc_names);
}

// expected combinations precedence:
// - final selected set is the union of rules events and base events
//   (either default or custom positive set)
// - events in the custom negative set are removed from the selected set
// - if `-A` is not set, events from the IO set are removed from the selected set
TEST(ConfigureInterestingSets, selection_custom_base_set)
{
	falco::app::state s5;
	// run app action with fake engine and without the `-A` option
	s5.options.all_events = true;
	s5.engine = mock_engine_from_filters(s_sample_filters);
	auto default_base_set = libsinsp::events::sinsp_state_sc_set();

	// non-empty custom base set (both positive and negative)
	s5.config->m_base_syscalls_repair = false;
	s5.config->m_base_syscalls_custom_set = {"syncfs", "!accept"};
	auto result = falco::app::actions::configure_interesting_sets(s5);
	ASSERT_TRUE(result.success);
	ASSERT_EQ(result.errstr, "");
	auto selected_sc_names = libsinsp::events::sc_set_to_event_names(s5.selected_sc_set);
	auto expected_sc_names = strset_t({
		// note: `syncfs` has been added due to the custom base set, and `accept`
		// has been remove due to the negative base set.
		// note: `read` is not ignored due to the "-A" option being set.
		// note: `accept` is not included even though it is matched by the rules,
		// which means that the custom negation base set has precedence over the
		// final selection set as a whole
		// note(jasondellaluce): "accept4" should be added, however old versions
		// of the ACCEPT4 event are actually named "accept" in the event table
		"connect", "umount2", "open", "ptrace", "mmap", "execve", "read", "syncfs", "procexit"
	});
	ASSERT_NAMES_EQ(selected_sc_names, expected_sc_names);

	// non-empty custom base set (both positive and negative with collision)
	s5.config->m_base_syscalls_repair = false;
	s5.config->m_base_syscalls_custom_set = {"syncfs", "accept", "!accept"};
	result = falco::app::actions::configure_interesting_sets(s5);
	ASSERT_TRUE(result.success);
	ASSERT_EQ(result.errstr, "");
	selected_sc_names = libsinsp::events::sc_set_to_event_names(s5.selected_sc_set);
	// note: in case of collision, negation has priority, so the expected
	// names are the same as the case above
	ASSERT_NAMES_EQ(selected_sc_names, expected_sc_names);

	// non-empty custom base set (only positive)
	s5.config->m_base_syscalls_custom_set = {"syncfs"};
	result = falco::app::actions::configure_interesting_sets(s5);
	ASSERT_TRUE(result.success);
	ASSERT_EQ(result.errstr, "");
	selected_sc_names = libsinsp::events::sc_set_to_event_names(s5.selected_sc_set);
	expected_sc_names = strset_t({
		// note: accept is not negated anymore
		"connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", "read", "syncfs", "procexit"
	});
	ASSERT_NAMES_EQ(selected_sc_names, expected_sc_names);

	// non-empty custom base set (only negative)
	s5.config->m_base_syscalls_custom_set = {"!accept"};
	result = falco::app::actions::configure_interesting_sets(s5);
	ASSERT_TRUE(result.success);
	ASSERT_EQ(result.errstr, "");
	selected_sc_names = libsinsp::events::sc_set_to_event_names(s5.selected_sc_set);
	expected_sc_names = unordered_set_union(
		libsinsp::events::sc_set_to_event_names(default_base_set),
		strset_t({ "connect", "umount2", "open", "ptrace", "mmap", "execve", "read"}));
	expected_sc_names.erase("accept");
	// note(jasondellaluce): "accept4" should be included, however old versions
	// of the ACCEPT4 event are actually named "accept" in the event table
	expected_sc_names.erase("accept4");
	ASSERT_NAMES_EQ(selected_sc_names, expected_sc_names);

	// non-empty custom base set (positive, without -A)
	s5.options.all_events = false;
	s5.config->m_base_syscalls_custom_set = {"read"};
	result = falco::app::actions::configure_interesting_sets(s5);
	ASSERT_TRUE(result.success);
	ASSERT_EQ(result.errstr, "");
	selected_sc_names = libsinsp::events::sc_set_to_event_names(s5.selected_sc_set);
	expected_sc_names = strset_t({
		// note: read is both part of the custom base set and the rules set,
		// but we expect the unset -A option to take precedence
		"connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", "procexit"
	});
	ASSERT_NAMES_EQ(selected_sc_names, expected_sc_names);
	auto unexpected_sc_names = libsinsp::events::sc_set_to_event_names(falco::app::ignored_sc_set());
	ASSERT_NAMES_NOCONTAIN(selected_sc_names, unexpected_sc_names);
}

TEST(ConfigureInterestingSets, selection_custom_base_set_repair)
{
	falco::app::state s6;
	// run app action with fake engine and without the `-A` option
	s6.options.all_events = false;
	s6.engine = mock_engine_from_filters(s_sample_filters);

	// note: here we use file syscalls (e.g. open, openat) and have a custom
	// positive set, so we expect syscalls such as "close" to be selected as
	// repaired. Also, given that we use some network syscalls, we expect "bind"
	// to be selected event if we negate it, because repairment should have
	// take precedence.
	s6.config->m_base_syscalls_custom_set = {"openat", "!bind"};
	s6.config->m_base_syscalls_repair = true;
	auto result = falco::app::actions::configure_interesting_sets(s6);
	ASSERT_TRUE(result.success);
	ASSERT_EQ(result.errstr, "");
	auto selected_sc_names = libsinsp::events::sc_set_to_event_names(s6.selected_sc_set);
	auto expected_sc_names = strset_t({
		// note: expecting syscalls from mock rules and `sinsp_repair_state_sc_set` enforced syscalls
		"connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", "procexit", \
		"bind", "socket", "clone3", "close", "setuid"
	});
	ASSERT_NAMES_CONTAIN(selected_sc_names, expected_sc_names);
	auto unexpected_sc_names = libsinsp::events::sc_set_to_event_names(falco::app::ignored_sc_set());
	ASSERT_NAMES_NOCONTAIN(selected_sc_names, unexpected_sc_names);
}

TEST(ConfigureInterestingSets, selection_empty_custom_base_set_repair)
{
	falco::app::state s7;
	// run app action with fake engine and with the `-A` option
	s7.options.all_events = true;
	s7.engine = mock_engine_from_filters(s_sample_filters);

	// simulate empty custom set but repair option set.
	s7.config->m_base_syscalls_custom_set = {};
	s7.config->m_base_syscalls_repair = true;
	auto result = falco::app::actions::configure_interesting_sets(s7);
	auto s7_rules_set = s7.engine->sc_codes_for_ruleset(s_sample_source, s_sample_ruleset);
	ASSERT_TRUE(result.success);
	ASSERT_EQ(result.errstr, "");
	auto selected_sc_names = libsinsp::events::sc_set_to_event_names(s7.selected_sc_set);
	auto expected_sc_names = strset_t({
		// note: expecting syscalls from mock rules and `sinsp_repair_state_sc_set` enforced syscalls
		"connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", "procexit", \
		"bind", "socket", "clone3", "close", "setuid"
	});
	ASSERT_NAMES_CONTAIN(selected_sc_names, expected_sc_names);
	auto s7_state_set = libsinsp::events::sinsp_repair_state_sc_set(s7_rules_set);
	ASSERT_EQ(s7.selected_sc_set, s7_state_set);
	ASSERT_EQ(s7.selected_sc_set.size(), s7_state_set.size());
}

TEST(ConfigureInterestingSets, ignored_set_expected_size)
{
	// unit test fence to make sure we don't have unexpected regressions
	// in the ignored set, to be updated in the future
	ASSERT_EQ(falco::app::ignored_sc_set().size(), 14);

	// we don't expect to ignore any syscall in the default base set
	ASSERT_EQ(falco::app::ignored_sc_set().intersect(libsinsp::events::sinsp_state_sc_set()).size(), 0);
}
