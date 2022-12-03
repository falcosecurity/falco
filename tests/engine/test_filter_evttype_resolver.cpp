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

#include "filter_evttype_resolver.h"
#include <catch.hpp>
#include <sinsp.h>
#include <filter/parser.h>

using namespace libsinsp::filter;

std::string to_string(std::set<uint16_t> s)
{
	std::string out = "[";
	for(auto &val : s)
	{
        out += out.size() == 1 ? "" : ", ";
		out += std::to_string(val);
	}
	out += "]";
	return out;
}

void compare_evttypes(std::unique_ptr<ast::expr> f, std::set<uint16_t> &expected)
{
    std::set<uint16_t> actual;
    filter_evttype_resolver().evttypes(f.get(), actual);
    for(auto &etype : expected)
    {
        REQUIRE(actual.find(etype) != actual.end());
    }
    for(auto &etype : actual)
    {
        REQUIRE(expected.find(etype) != expected.end());
    }
}

std::unique_ptr<ast::expr> compile(const std::string &fltstr)
{
    return libsinsp::filter::parser(fltstr).parse();
}

TEST_CASE("Should find event types from filter", "[rule_loader]")
{
    std::set<uint16_t> openat_only{
        PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X,
		PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X };

	std::set<uint16_t> close_only{
		PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X };

	std::set<uint16_t> openat_close{
        PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X,
        PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X,
        PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X };

	std::set<uint16_t> not_openat;
	std::set<uint16_t> not_openat_close;
	std::set<uint16_t> not_close;
	std::set<uint16_t> all_events;
	std::set<uint16_t> no_events;

    for(uint32_t i = 2; i < PPM_EVENT_MAX; i++)
    {
        // Skip events that are unused.
        if(sinsp::is_unused_event(i))
        {
            continue;
        }

        all_events.insert(i);
        if(openat_only.find(i) == openat_only.end())
        {
            not_openat.insert(i);
        }
        if(openat_close.find(i) == openat_close.end())
        {
            not_openat_close.insert(i);
        }
        if (close_only.find(i) == close_only.end())
        {
            not_close.insert(i);
        }
    }

    SECTION("evt_type_eq")
    {
        auto f = compile("evt.type=openat");
        compare_evttypes(std::move(f), openat_only);
    }

    SECTION("evt_type_in")
    {
        auto f = compile("evt.type in (openat, close)");
        compare_evttypes(std::move(f), openat_close);
    }

    SECTION("evt_type_ne")
    {
        auto f = compile("evt.type!=openat");
        compare_evttypes(std::move(f), not_openat);
    }

    SECTION("not_evt_type_eq")
    {
        auto f = compile("not evt.type=openat");
        compare_evttypes(std::move(f), not_openat);
    }

    SECTION("not_evt_type_in")
    {
        auto f = compile("not evt.type in (openat, close)");
        compare_evttypes(std::move(f), not_openat_close);
    }

    SECTION("not_evt_type_ne")
    {
        auto f = compile("not evt.type != openat");
        compare_evttypes(std::move(f), openat_only);
    }

    SECTION("evt_type_or")
    {
        auto f = compile("evt.type=openat or evt.type=close");
        compare_evttypes(std::move(f), openat_close);
    }

    SECTION("not_evt_type_or")
    {
        auto f = compile("evt.type!=openat or evt.type!=close");
        compare_evttypes(std::move(f), all_events);
    }

    SECTION("evt_type_or_ne")
    {
        auto f = compile("evt.type=close or evt.type!=openat");
        compare_evttypes(std::move(f), not_openat);
    }

    SECTION("evt_type_and")
    {
        auto f = compile("evt.type=close and evt.type=openat");
        compare_evttypes(std::move(f), no_events);
    }

    SECTION("evt_type_and_non_evt_type")
    {
        auto f = compile("evt.type=openat and proc.name=nginx");
        compare_evttypes(std::move(f), openat_only);
    }

    SECTION("evt_type_and_non_evt_type_not")
    {
        auto f = compile("evt.type=openat and not proc.name=nginx");
        compare_evttypes(std::move(f), openat_only);
    }

    SECTION("evt_type_and_nested")
    {
        auto f = compile("evt.type=openat and (proc.name=nginx)");
        compare_evttypes(std::move(f), openat_only);
    }

    SECTION("evt_type_and_nested_multi")
    {
        auto f = compile("evt.type=openat and (evt.type=close and proc.name=nginx)");
        compare_evttypes(std::move(f), no_events);
    }

    SECTION("non_evt_type")
    {
        auto f = compile("proc.name=nginx");
        compare_evttypes(std::move(f), all_events);
    }

    SECTION("non_evt_type_or")
    {
        auto f = compile("evt.type=openat or proc.name=nginx");
        compare_evttypes(std::move(f), all_events);
    }

    SECTION("non_evt_type_or_nested_first")
    {
        auto f = compile("(evt.type=openat) or proc.name=nginx");
        compare_evttypes(std::move(f), all_events);
    }

    SECTION("non_evt_type_or_nested_second")
    {
        auto f = compile("evt.type=openat or (proc.name=nginx)");
        compare_evttypes(std::move(f), all_events);
    }

    SECTION("non_evt_type_or_nested_multi")
    {
        auto f = compile("evt.type=openat or (evt.type=close and proc.name=nginx)");
        compare_evttypes(std::move(f), openat_close);
    }

    SECTION("non_evt_type_or_nested_multi_not")
    {
        auto f = compile("evt.type=openat or not (evt.type=close and proc.name=nginx)");
        compare_evttypes(std::move(f), not_close);
    }

    SECTION("non_evt_type_and_nested_multi_not")
    {
        auto f = compile("evt.type=openat and not (evt.type=close and proc.name=nginx)");
        compare_evttypes(std::move(f), openat_only);
    }

    SECTION("ne_and_and")
    {
        auto f = compile("evt.type!=openat and evt.type!=close");
        compare_evttypes(std::move(f), not_openat_close);
    }

    SECTION("not_not")
    {
        auto f = compile("not (not evt.type=openat)");
        compare_evttypes(std::move(f), openat_only);
    }
}
