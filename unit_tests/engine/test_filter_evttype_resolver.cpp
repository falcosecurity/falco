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

#include <gtest/gtest.h>
#include <engine/filter_evttype_resolver.h>
#include <sinsp.h>
#include <filter/parser.h>

#define ASSERT_FILTER_EQ(a, b) { ASSERT_EQ(get_filter_set(a), get_filter_set(b)); }

std::set<uint16_t> get_filter_set(const string &fltstr)
{
	set<uint16_t> actual;
	auto f = libsinsp::filter::parser(fltstr).parse();
	filter_evttype_resolver().evttypes(f.get(), actual);
	return actual;
}

std::set<uint16_t> get_set_difference(std::set<uint16_t> exclude_set = {})
{
	std::set<uint16_t> set_difference = {};

	for(uint32_t i = PPME_GENERIC_E; i < PPM_EVENT_MAX; i++)
	{
		/* Skip events that are unused. */
		if(sinsp::is_unused_event(i))
		{
			continue;
		}

		if(exclude_set.find(i) == exclude_set.end())
		{
			set_difference.insert(i);
		}
	}
    return set_difference;
}

TEST(EvtTypeResolver, check_openat)
{
	std::set<uint16_t> openat_only{
		PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X,
		PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X};

	std::set<uint16_t> not_openat = get_set_difference(openat_only);

	/* `openat_only` */
	ASSERT_EQ(get_filter_set("evt.type=openat"), openat_only);
	ASSERT_EQ(get_filter_set("evt.type = openat"), openat_only);
	ASSERT_EQ(get_filter_set("not evt.type != openat"), openat_only);
	ASSERT_EQ(get_filter_set("not not evt.type = openat"), openat_only);
	ASSERT_EQ(get_filter_set("not not not not evt.type = openat"), openat_only);
	ASSERT_EQ(get_filter_set("evt.type in (openat)"), openat_only);
	ASSERT_EQ(get_filter_set("not (not evt.type=openat)"), openat_only);
	ASSERT_EQ(get_filter_set("evt.type=openat and proc.name=nginx"), openat_only);
	ASSERT_EQ(get_filter_set("evt.type=openat and not proc.name=nginx"), openat_only);
	ASSERT_EQ(get_filter_set("evt.type=openat and (proc.name=nginx)"), openat_only);
	ASSERT_EQ(get_filter_set("evt.type=openat and not (evt.type=close and proc.name=nginx)"), openat_only);

	/* `not_openat` */
	ASSERT_EQ(get_filter_set("evt.type!=openat"), not_openat);
	ASSERT_EQ(get_filter_set("not not not evt.type = openat"), not_openat);
	ASSERT_EQ(get_filter_set("not evt.type=openat"), not_openat);
	ASSERT_EQ(get_filter_set("evt.type=close or evt.type!=openat"), not_openat);
}

TEST(EvtTypeResolver, check_openat_or_close)
{
	std::set<uint16_t> openat_close_only{
		PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X,
		PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X,
		PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X};

	std::set<uint16_t> not_openat_close = get_set_difference(openat_close_only);

	/* `openat_close_only` */
	ASSERT_EQ(get_filter_set("evt.type in (openat, close)"), openat_close_only);
	ASSERT_EQ(get_filter_set("evt.type=openat or evt.type=close"), openat_close_only);
	ASSERT_EQ(get_filter_set("evt.type=openat or (evt.type=close and proc.name=nginx)"), openat_close_only);
	ASSERT_EQ(get_filter_set("evt.type=close or (evt.type=openat and proc.name=nginx)"), openat_close_only);

	/* not `not_openat_close` */
	ASSERT_EQ(get_filter_set("not evt.type in (openat, close)"), not_openat_close);
	ASSERT_EQ(get_filter_set("not not not evt.type in (openat, close)"), not_openat_close);
	ASSERT_EQ(get_filter_set("evt.type!=openat and evt.type!=close"), not_openat_close);
}

TEST(EvtTypeResolver, check_all_events)
{
    /* Computed as a difference of the empty set */
	std::set<uint16_t> all_events = get_set_difference();

	ASSERT_EQ(get_filter_set("evt.type!=openat or evt.type!=close"), all_events);
	ASSERT_EQ(get_filter_set("proc.name=nginx"), all_events);
	ASSERT_EQ(get_filter_set("evt.type=openat or proc.name=nginx"), all_events);
	ASSERT_EQ(get_filter_set("evt.type=openat or (proc.name=nginx)"), all_events);
	ASSERT_EQ(get_filter_set("(evt.type=openat) or proc.name=nginx"), all_events);
	ASSERT_EQ(get_filter_set("evt.type=close or not (evt.type=openat and proc.name=nginx)"), all_events);
	ASSERT_EQ(get_filter_set("evt.type=openat or not (evt.type=close and proc.name=nginx)"), all_events);
}

TEST(EvtTypeResolver, check_no_events)
{
	std::set<uint16_t> no_events = {};

	ASSERT_EQ(get_filter_set("evt.type=close and evt.type=openat"), no_events);
	ASSERT_EQ(get_filter_set("evt.type=openat and (evt.type=close and proc.name=nginx)"), no_events);
	ASSERT_EQ(get_filter_set("evt.type=openat and (evt.type=close)"), no_events);
}

TEST(EvtTypeResolver, check_properties)
{
	std::set<uint16_t> no_events = {};

	// see: https://github.com/falcosecurity/libs/pull/854#issuecomment-1411151732
	ASSERT_FILTER_EQ(
		"evt.type in (connect, execve, accept, mmap, container) and not (proc.name=cat and evt.type=mmap)",
		"evt.type in (accept, connect, container, execve, mmap)");
	ASSERT_EQ(get_filter_set("(evt.type=mmap and not evt.type=mmap)"), no_events);

	// defining algebraic base sets
	std::string zerof = "(evt.type in ())"; ///< "zero"-set: no evt type should matches the filter
	std::string onef = "(evt.type exists)"; ///< "one"-set: all evt types should match the filter
	std::string neutral1 = "(proc.name=cat)"; ///< "neutral"-sets: evt types are not checked in the filter
	std::string neutral2 = "(not proc.name=cat)";
	ASSERT_FILTER_EQ(onef, neutral1);
	ASSERT_FILTER_EQ(onef, neutral2);

	// algebraic set properties
	// 1' = 0
	ASSERT_FILTER_EQ("not " + onef, zerof);
	// 0' = 1
	ASSERT_FILTER_EQ("not " + zerof, onef);
	// (A')' = A
	ASSERT_FILTER_EQ("evt.type=mmap", "not (not evt.type=mmap)");
	// A * A' = 0
	ASSERT_EQ(get_filter_set(zerof), no_events);
	// A + A' = 1
	ASSERT_FILTER_EQ("evt.type=mmap or not evt.type=mmap", onef);
	ASSERT_FILTER_EQ("evt.type=mmap or not evt.type=mmap", neutral1);
	ASSERT_FILTER_EQ("evt.type=mmap or not evt.type=mmap", neutral2);
	// 0 * 1 = 0
	ASSERT_FILTER_EQ(zerof + " and " + onef, zerof);
	ASSERT_FILTER_EQ(zerof + " and " + neutral1, zerof);
	ASSERT_FILTER_EQ(zerof + " and " + neutral2, zerof);
	// 0 + 1 = 1
	ASSERT_FILTER_EQ(zerof + " or " + onef, onef);
	ASSERT_FILTER_EQ(zerof + " or " + neutral1, onef);
	ASSERT_FILTER_EQ(zerof + " or " + neutral2, onef);
	// A * 0 = 0
	ASSERT_FILTER_EQ("evt.type=mmap and " + zerof, zerof);
	// A * 1 = A
	ASSERT_FILTER_EQ("evt.type=mmap and " + onef, "evt.type=mmap");
	ASSERT_FILTER_EQ("evt.type=mmap and " + neutral1, "evt.type=mmap");
	ASSERT_FILTER_EQ("evt.type=mmap and " + neutral2, "evt.type=mmap");
	// A + 0 = A
	ASSERT_FILTER_EQ("evt.type=mmap or " + zerof, "evt.type=mmap");
	// A + 1 = 1
	ASSERT_FILTER_EQ("evt.type=mmap or " + onef, onef);
	ASSERT_FILTER_EQ("evt.type=mmap or " + neutral1, onef);
	ASSERT_FILTER_EQ("evt.type=mmap or " + neutral2, onef);
	// A + A = A
	ASSERT_FILTER_EQ("evt.type=mmap or evt.type=mmap", "evt.type=mmap");
	// A * A = A
	ASSERT_FILTER_EQ("evt.type=mmap and evt.type=mmap", "evt.type=mmap");

	// de morgan's laws
	ASSERT_FILTER_EQ(
		"not (proc.name=cat or evt.type=mmap)",
		"not proc.name=cat and not evt.type=mmap");
	ASSERT_FILTER_EQ(
		"not (proc.name=cat or fd.type=file)",
		"not proc.name=cat and not fd.type=file");
	ASSERT_FILTER_EQ(
		"not (evt.type=execve or evt.type=mmap)",
		"not evt.type=execve and not evt.type=mmap");
	ASSERT_FILTER_EQ(
		"not (evt.type=mmap or evt.type=mmap)",
		"not evt.type=mmap and not evt.type=mmap");
	ASSERT_FILTER_EQ(
		"not (proc.name=cat and evt.type=mmap)",
		"not proc.name=cat or not evt.type=mmap");
	ASSERT_FILTER_EQ(
		"not (proc.name=cat and fd.type=file)",
		"not proc.name=cat or not fd.type=file");
	ASSERT_FILTER_EQ(
		"not (evt.type=execve and evt.type=mmap)",
		"not evt.type=execve or not evt.type=mmap");
	ASSERT_FILTER_EQ(
		"not (evt.type=mmap and evt.type=mmap)",
		"not evt.type=mmap or not evt.type=mmap");

	// negation isomorphism
	ASSERT_FILTER_EQ("not evt.type=mmap", "evt.type!=mmap");
	ASSERT_FILTER_EQ("not proc.name=cat", "proc.name!=cat");

	// commutative property (and)
	ASSERT_FILTER_EQ("evt.type=execve and evt.type=mmap", "evt.type=mmap and evt.type=execve");
	ASSERT_FILTER_EQ("not (evt.type=execve and evt.type=mmap)", "not (evt.type=mmap and evt.type=execve)");
	ASSERT_FILTER_EQ("not evt.type=execve and not evt.type=mmap", "not evt.type=mmap and not evt.type=execve");
	ASSERT_FILTER_EQ("proc.name=cat and evt.type=mmap", "evt.type=mmap and proc.name=cat");
	ASSERT_FILTER_EQ("not (proc.name=cat and evt.type=mmap)", "not (evt.type=mmap and proc.name=cat)");
	ASSERT_FILTER_EQ("not proc.name=cat and not evt.type=mmap", "not evt.type=mmap and not proc.name=cat");
	ASSERT_FILTER_EQ("proc.name=cat and fd.type=file", "fd.type=file and proc.name=cat");
	ASSERT_FILTER_EQ("not (proc.name=cat and fd.type=file)", "not (fd.type=file and proc.name=cat)");
	ASSERT_FILTER_EQ("not proc.name=cat and not fd.type=file", "not fd.type=file and not proc.name=cat");

	// commutative property (or)
	ASSERT_FILTER_EQ("evt.type=execve or evt.type=mmap", "evt.type=mmap or evt.type=execve");
	ASSERT_FILTER_EQ("not (evt.type=execve or evt.type=mmap)", "not (evt.type=mmap or evt.type=execve)");
	ASSERT_FILTER_EQ("not evt.type=execve or not evt.type=mmap", "not evt.type=mmap or not evt.type=execve");
	ASSERT_FILTER_EQ("proc.name=cat or evt.type=mmap", "evt.type=mmap or proc.name=cat");
	ASSERT_FILTER_EQ("not (proc.name=cat or evt.type=mmap)", "not (evt.type=mmap or proc.name=cat)");
	ASSERT_FILTER_EQ("not proc.name=cat or not evt.type=mmap", "not evt.type=mmap or not proc.name=cat");
	ASSERT_FILTER_EQ("proc.name=cat or fd.type=file", "fd.type=file or proc.name=cat");
	ASSERT_FILTER_EQ("not (proc.name=cat or fd.type=file)", "not (fd.type=file or proc.name=cat)");
	ASSERT_FILTER_EQ("not proc.name=cat or not fd.type=file", "not fd.type=file or not proc.name=cat");
}
