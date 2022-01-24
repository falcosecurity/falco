/*
Copyright (C) 2019 The Falco Authors.

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
#include "banned.h" // This raises a compilation error when certain functions are used

#include <algorithm>

using namespace std;

falco_ruleset::falco_ruleset()
{
}

falco_ruleset::~falco_ruleset()
{
}

falco_ruleset::ruleset_filters::ruleset_filters()
{
}

falco_ruleset::ruleset_filters::~ruleset_filters()
{
}

void falco_ruleset::ruleset_filters::add_wrapper_to_list(filter_wrapper_list &wrappers, std::shared_ptr<filter_wrapper> wrap)
{
	// This is O(n) but it's also uncommon
	// (when loading rules only).
	auto pos = std::find(wrappers.begin(),
			     wrappers.end(),
			     wrap);

	if(pos == wrappers.end())
	{
		wrappers.push_back(wrap);
	}
}

void falco_ruleset::ruleset_filters::remove_wrapper_from_list(filter_wrapper_list &wrappers, std::shared_ptr<filter_wrapper> wrap)
{
	// This is O(n) but it's also uncommon
	// (when loading rules only).
	auto pos = std::find(wrappers.begin(),
			     wrappers.end(),
			     wrap);
	if(pos != wrappers.end())
	{
		wrappers.erase(pos);
	}
}

void falco_ruleset::ruleset_filters::add_filter(std::shared_ptr<filter_wrapper> wrap)
{
	std::set<uint16_t> fevttypes = wrap->filter->evttypes();

	// TODO: who fills this one for rules without evt.type specified?
	// Can this be actually empty?
	// Is m_filter_all_event_types useful?
	if(fevttypes.empty())
	{
		// Should run for all event types
		add_wrapper_to_list(m_filter_all_event_types, wrap);
	}
	else
	{
		for(auto &etype : fevttypes)
		{
			if(m_filter_by_event_type.size() <= etype)
			{
				m_filter_by_event_type.resize(etype + 1);
			}

			add_wrapper_to_list(m_filter_by_event_type[etype], wrap);
		}
	}

	m_filters.insert(wrap);
}

void falco_ruleset::ruleset_filters::remove_filter(std::shared_ptr<filter_wrapper> wrap)
{
	std::set<uint16_t> fevttypes = wrap->filter->evttypes();

	if(fevttypes.empty())
	{
		remove_wrapper_from_list(m_filter_all_event_types, wrap);
	}
	else
	{
		for(auto &etype : fevttypes)
		{
			if( etype < m_filter_by_event_type.size() )
			{
				remove_wrapper_from_list(m_filter_by_event_type[etype], wrap);
			}
		}
	}

	m_filters.erase(wrap);
}

uint64_t falco_ruleset::ruleset_filters::num_filters()
{
	return m_filters.size();
}

bool falco_ruleset::ruleset_filters::run(gen_event *evt)
{
	if(evt->get_type() >= m_filter_by_event_type.size())
	{
		return false;
	}

	for(auto &wrap : m_filter_by_event_type[evt->get_type()])
	{
		if(wrap->filter->run(evt))
		{
			return true;
		}
	}

	// Finally, try filters that are not specific to an event type.
	for(auto &wrap : m_filter_all_event_types)
	{
		if(wrap->filter->run(evt))
		{
			return true;
		}
	}

	return false;
}

void falco_ruleset::ruleset_filters::evttypes_for_ruleset(std::set<uint16_t> &evttypes)
{
	evttypes.clear();

	for(auto &wrap : m_filters)
	{
		auto fevttypes = wrap->filter->evttypes();
		evttypes.insert(fevttypes.begin(), fevttypes.end());
	}
}

void falco_ruleset::add(string &name,
			set<string> &tags,
			std::shared_ptr<gen_event_filter> filter)
{
	std::shared_ptr<filter_wrapper> wrap(new filter_wrapper());
	wrap->name = name;
	wrap->tags = tags;
	wrap->filter = filter;

	m_filters.insert(wrap);
}

void falco_ruleset::enable(const string &substring, bool match_exact, bool enabled, uint16_t ruleset)
{
	while(m_rulesets.size() < (size_t)ruleset + 1)
	{
		m_rulesets.emplace_back(new ruleset_filters());
	}

	for(const auto &wrap : m_filters)
	{
		bool matches;

		if(match_exact)
		{
			size_t pos = wrap->name.find(substring);

			matches = (substring == "" || (pos == 0 &&
						       substring.size() == wrap->name.size()));
		}
		else
		{
			matches = (substring == "" || (wrap->name.find(substring) != string::npos));
		}

		if(matches)
		{
			if(enabled)
			{
				m_rulesets[ruleset]->add_filter(wrap);
			}
			else
			{
				m_rulesets[ruleset]->remove_filter(wrap);
			}
		}
	}
}

void falco_ruleset::enable_tags(const set<string> &tags, bool enabled, uint16_t ruleset)
{
	while(m_rulesets.size() < (size_t)ruleset + 1)
	{
		m_rulesets.emplace_back(new ruleset_filters());
	}

	for(const auto &wrap : m_filters)
	{
		std::set<string> intersect;

		set_intersection(tags.begin(), tags.end(),
				 wrap->tags.begin(), wrap->tags.end(),
				 inserter(intersect, intersect.begin()));

		if(!intersect.empty())
		{
			if(enabled)
			{
				m_rulesets[ruleset]->add_filter(wrap);
			}
			else
			{
				m_rulesets[ruleset]->remove_filter(wrap);
			}
		}
	}
}

uint64_t falco_ruleset::num_rules_for_ruleset(uint16_t ruleset)
{
	while(m_rulesets.size() < (size_t)ruleset + 1)
	{
		m_rulesets.emplace_back(new ruleset_filters());
	}

	return m_rulesets[ruleset]->num_filters();
}

bool falco_ruleset::run(gen_event *evt, uint16_t ruleset)
{
	if(m_rulesets.size() < (size_t)ruleset + 1)
	{
		return false;
	}

	return m_rulesets[ruleset]->run(evt);
}

void falco_ruleset::evttypes_for_ruleset(set<uint16_t> &evttypes, uint16_t ruleset)
{
	if(m_rulesets.size() < (size_t)ruleset + 1)
	{
		return;
	}

	return m_rulesets[ruleset]->evttypes_for_ruleset(evttypes);
}
