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
	ASSERT_EQ(get_filter_set("evt.type=close or not (evt.type=openat and proc.name=nginx)"), not_openat);
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
}

TEST(EvtTypeResolver, check_no_events)
{
	std::set<uint16_t> no_events = {};

	ASSERT_EQ(get_filter_set("evt.type=close and evt.type=openat"), no_events);
	ASSERT_EQ(get_filter_set("evt.type=openat and (evt.type=close and proc.name=nginx)"), no_events);
	ASSERT_EQ(get_filter_set("evt.type=openat and (evt.type=close)"), no_events);
}
