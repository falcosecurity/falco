/*
Copyright (C) 2018 Draios inc.

This file is part of falco.

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

#pragma once

#include <string>
#include <set>
#include <vector>
#include <list>
#include <map>
#include <regex>

#include "sinsp.h"
#include "filter.h"
#include "event.h"

#include "gen_filter.h"

class falco_ruleset
{
public:
	falco_ruleset();
	virtual ~falco_ruleset();

	void add(std::string &name,
		 std::set<std::string> &tags,
		 std::set<uint32_t> &event_tags,
		 gen_event_filter* filter);

	// rulesets are arbitrary numbers and should be managed by the caller.
        // Note that rulesets are used to index into a std::vector so
        // specifying unnecessarily large rulesets will result in
        // unnecessarily large vectors.

	// Find those rules matching the provided pattern and set
	// their enabled status to enabled.
	void enable(const std::string &pattern, bool enabled, uint16_t ruleset = 0);

	// Find those rules that have a tag in the set of tags and set
	// their enabled status to enabled. Note that the enabled
	// status is on the rules, and not the tags--if a rule R has
	// tags (a, b), and you call enable_tags([a], true) and then
	// enable_tags([b], false), R will be disabled despite the
	// fact it has tag a and was enabled by the first call to
	// enable_tags.
	void enable_tags(const std::set<std::string> &tags, bool enabled, uint16_t ruleset = 0);

	// Match all filters against the provided event.
	bool run(gen_event *evt, uint32_t etag, uint16_t ruleset = 0);

	// Populate the provided vector, indexed by event tag, of the
	// event tags associated with the given ruleset id. For
	// example, event_tags[10] = true would mean that this ruleset
	// relates to event tag 10.
	void event_tags_for_ruleset(std::vector<bool> &event_tags, uint16_t ruleset);

private:

	struct filter_wrapper {
		gen_event_filter *filter;

		// Indexes from event tag to enabled/disabled.
		std::vector<bool> event_tags;
	};

	// A group of filters all having the same ruleset
	class ruleset_filters {
	public:
		ruleset_filters();

		virtual ~ruleset_filters();

		void add_filter(filter_wrapper *wrap);
		void remove_filter(filter_wrapper *wrap);

		bool run(gen_event *evt, uint32_t etag);

		void event_tags_for_ruleset(std::vector<bool> &event_tags);

	private:
		// Maps from event tag to a list of filters. There can
		// be multiple filters for a given event tag.
		std::vector<std::list<filter_wrapper *> *> m_filter_by_event_tag;

	};

	std::vector<ruleset_filters *> m_rulesets;

	// Maps from tag to list of filters having that tag.
	std::map<std::string, std::list<filter_wrapper *>> m_filter_by_event_tag;

	// This holds all the filters passed to add(), so they can
	// be cleaned up.
	std::map<std::string,filter_wrapper *> m_filters;
};

// falco_sinsp_ruleset is a specialization of falco_ruleset that
// maps sinsp evttypes/syscalls to event tags.
class falco_sinsp_ruleset : public falco_ruleset
{
public:
	falco_sinsp_ruleset();
	virtual ~falco_sinsp_ruleset();

	void add(std::string &name,
		 std::set<uint32_t> &evttypes,
		 std::set<uint32_t> &syscalls,
		 std::set<std::string> &tags,
		 sinsp_filter* filter);

	bool run(sinsp_evt *evt, uint16_t ruleset = 0);

	// Populate the provided vector, indexed by event type, of the
	// event types associated with the given ruleset id. For
	// example, evttypes[10] = true would mean that this ruleset
	// relates to event type 10.
	void evttypes_for_ruleset(std::vector<bool> &evttypes, uint16_t ruleset);

	// Populate the provided vector, indexed by syscall code, of the
	// syscall codes associated with the given ruleset id. For
	// example, syscalls[10] = true would mean that this ruleset
	// relates to syscall code 10.
	void syscalls_for_ruleset(std::vector<bool> &syscalls, uint16_t ruleset);

private:
	uint32_t evttype_to_event_tag(uint32_t evttype);
	uint32_t syscall_to_event_tag(uint32_t syscallid);
};
