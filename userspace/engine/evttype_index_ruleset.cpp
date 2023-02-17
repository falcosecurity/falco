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

#include "evttype_index_ruleset.h"
#include "banned.h" // This raises a compilation error when certain functions are used

#include <algorithm>

evttype_index_ruleset::evttype_index_ruleset(
	std::shared_ptr<gen_event_filter_factory> f): m_filter_factory(f)
{
}

evttype_index_ruleset::~evttype_index_ruleset()
{
}

evttype_index_ruleset::ruleset_filters::ruleset_filters()
{
}

evttype_index_ruleset::ruleset_filters::~ruleset_filters()
{
}

void evttype_index_ruleset::ruleset_filters::add_wrapper_to_list(filter_wrapper_list &wrappers, std::shared_ptr<filter_wrapper> wrap)
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

void evttype_index_ruleset::ruleset_filters::remove_wrapper_from_list(filter_wrapper_list &wrappers, std::shared_ptr<filter_wrapper> wrap)
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

void evttype_index_ruleset::ruleset_filters::add_filter(std::shared_ptr<filter_wrapper> wrap)
{
	if(wrap->evttypes.empty())
	{
		// Should run for all event types
		add_wrapper_to_list(m_filter_all_event_types, wrap);
	}
	else
	{
		for(auto &etype : wrap->evttypes)
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

void evttype_index_ruleset::ruleset_filters::remove_filter(std::shared_ptr<filter_wrapper> wrap)
{
	if(wrap->evttypes.empty())
	{
		remove_wrapper_from_list(m_filter_all_event_types, wrap);
	}
	else
	{
		for(auto &etype : wrap->evttypes)
		{
			if( etype < m_filter_by_event_type.size() )
			{
				remove_wrapper_from_list(m_filter_by_event_type[etype], wrap);
			}
		}
	}

	m_filters.erase(wrap);
}

uint64_t evttype_index_ruleset::ruleset_filters::num_filters()
{
	return m_filters.size();
}

bool evttype_index_ruleset::ruleset_filters::run(gen_event *evt, falco_rule& match)
{
    if(evt->get_type() < m_filter_by_event_type.size())
    {
        for(auto &wrap : m_filter_by_event_type[evt->get_type()])
        {
            if(wrap->filter->run(evt))
            {
				match = wrap->rule;
                return true;
            }
        }
    }

	// Finally, try filters that are not specific to an event type.
	for(auto &wrap : m_filter_all_event_types)
	{
		if(wrap->filter->run(evt))
		{
			match = wrap->rule;
			return true;
		}
	}

	return false;
}

void evttype_index_ruleset::ruleset_filters::evttypes_for_ruleset(std::set<uint16_t> &evttypes)
{
	evttypes.clear();

	for(auto &wrap : m_filters)
	{
		for (const auto& e : wrap->evttypes)
		{
			evttypes.insert((uint16_t) e);
		}
	}
}

void evttype_index_ruleset::add(
		const falco_rule& rule,
		std::shared_ptr<gen_event_filter> filter,
		std::shared_ptr<libsinsp::filter::ast::expr> condition)
{
	try
	{
		std::shared_ptr<filter_wrapper> wrap(new filter_wrapper());
		wrap->rule = rule;
		wrap->filter = filter;
		if(rule.source == falco_common::syscall_source)
		{
			wrap->evttypes = libsinsp::filter::ast::ppm_event_codes(condition.get());
		}
		else
		{
			wrap->evttypes = { ppm_event_code::PPME_PLUGINEVENT_E };
		}
		m_filters.insert(wrap);
	}
	catch (const sinsp_exception& e)
	{
		throw falco_exception(std::string(e.what()));
	}
}

void evttype_index_ruleset::on_loading_complete()
{
	// nothing to do for now
}

void evttype_index_ruleset::clear()
{
	for (size_t i = 0; i < m_rulesets.size(); i++)
	{
		std::shared_ptr<ruleset_filters> r(new ruleset_filters());
		m_rulesets[i] = r;
	}
	m_filters.clear();
}

void evttype_index_ruleset::enable(const std::string &substring, bool match_exact, uint16_t ruleset_id)
{
	enable_disable(substring, match_exact, true, ruleset_id);
}

void evttype_index_ruleset::disable(const std::string &substring, bool match_exact, uint16_t ruleset_id)
{
	enable_disable(substring, match_exact, false, ruleset_id);
}

void evttype_index_ruleset::enable_disable(const std::string &substring, bool match_exact, bool enabled, uint16_t ruleset_id)
{
	while(m_rulesets.size() < (size_t)ruleset_id + 1)
	{
		m_rulesets.emplace_back(new ruleset_filters());
	}

	for(const auto &wrap : m_filters)
	{
		bool matches;

		if(match_exact)
		{
			size_t pos = wrap->rule.name.find(substring);

			matches = (substring == "" || (pos == 0 &&
						       substring.size() == wrap->rule.name.size()));
		}
		else
		{
			matches = (substring == "" || (wrap->rule.name.find(substring) != std::string::npos));
		}

		if(matches)
		{
			if(enabled)
			{
				m_rulesets[ruleset_id]->add_filter(wrap);
			}
			else
			{
				m_rulesets[ruleset_id]->remove_filter(wrap);
			}
		}
	}
}

void evttype_index_ruleset::enable_tags(const std::set<std::string> &tags, uint16_t ruleset_id)
{
	enable_disable_tags(tags, true, ruleset_id);
}

void evttype_index_ruleset::disable_tags(const std::set<std::string> &tags, uint16_t ruleset_id)
{
	enable_disable_tags(tags, false, ruleset_id);
}

void evttype_index_ruleset::enable_disable_tags(const std::set<std::string> &tags, bool enabled, uint16_t ruleset_id)
{
	while(m_rulesets.size() < (size_t)ruleset_id + 1)
	{
		m_rulesets.emplace_back(new ruleset_filters());
	}

	for(const auto &wrap : m_filters)
	{
		std::set<std::string> intersect;

		set_intersection(tags.begin(), tags.end(),
				 wrap->rule.tags.begin(), wrap->rule.tags.end(),
				 inserter(intersect, intersect.begin()));

		if(!intersect.empty())
		{
			if(enabled)
			{
				m_rulesets[ruleset_id]->add_filter(wrap);
			}
			else
			{
				m_rulesets[ruleset_id]->remove_filter(wrap);
			}
		}
	}
}

uint64_t evttype_index_ruleset::enabled_count(uint16_t ruleset_id)
{
	while(m_rulesets.size() < (size_t)ruleset_id + 1)
	{
		m_rulesets.emplace_back(new ruleset_filters());
	}

	return m_rulesets[ruleset_id]->num_filters();
}

bool evttype_index_ruleset::run(gen_event *evt, falco_rule& match, uint16_t ruleset_id)
{
	if(m_rulesets.size() < (size_t)ruleset_id + 1)
	{
		return false;
	}

	return m_rulesets[ruleset_id]->run(evt, match);
}

void evttype_index_ruleset::enabled_evttypes(std::set<uint16_t> &evttypes, uint16_t ruleset_id)
{
	if(m_rulesets.size() < (size_t)ruleset_id + 1)
	{
		return;
	}

	return m_rulesets[ruleset_id]->evttypes_for_ruleset(evttypes);
}
