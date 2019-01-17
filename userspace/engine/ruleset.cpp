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

#include "ruleset.h"

using namespace std;

falco_ruleset::falco_ruleset()
{
}

falco_ruleset::~falco_ruleset()
{
	for(const auto &val : m_filters)
	{
		delete val.second->filter;
		delete val.second;
	}

	for(auto &ruleset : m_rulesets)
	{
		delete ruleset;
	}
	m_filters.clear();
}

falco_ruleset::ruleset_filters::ruleset_filters()
{
}

falco_ruleset::ruleset_filters::~ruleset_filters()
{
	for(uint32_t i = 0; i < m_filter_by_event_tag.size(); i++)
	{
		if(m_filter_by_event_tag[i])
		{
			delete m_filter_by_event_tag[i];
			m_filter_by_event_tag[i] = NULL;
		}
	}
}

void falco_ruleset::ruleset_filters::add_filter(filter_wrapper *wrap)
{
	for(uint32_t etag = 0; etag < wrap->event_tags.size(); etag++)
	{
		if(wrap->event_tags[etag])
		{
			if(m_filter_by_event_tag.size() <= etag)
			{
				m_filter_by_event_tag.resize(etag+1);
			}

			if(!m_filter_by_event_tag[etag])
			{
				m_filter_by_event_tag[etag] = new list<filter_wrapper *>();
			}

			m_filter_by_event_tag[etag]->push_back(wrap);
		}
	}
}

void falco_ruleset::ruleset_filters::remove_filter(filter_wrapper *wrap)
{
	for(uint32_t etag = 0; etag < wrap->event_tags.size(); etag++)
	{
		if(wrap->event_tags[etag])
		{
			if(etag < m_filter_by_event_tag.size())
			{
				list<filter_wrapper *> *l = m_filter_by_event_tag[etag];
				if(l)
				{
					l->erase(remove(l->begin(),
							l->end(),
							wrap),
						 l->end());

					if(l->size() == 0)
					{
						delete l;
						m_filter_by_event_tag[etag] = NULL;
					}
				}
			}
		}
	}
}


bool falco_ruleset::ruleset_filters::run(gen_event *evt, uint32_t etag)
{
	if(etag >= m_filter_by_event_tag.size())
	{
		return false;
	}

	list<filter_wrapper *> *filters = m_filter_by_event_tag[etag];

	if (!filters) {
		return false;
	}

	for (auto &wrap : *filters)
	{
		if(wrap->filter->run(evt))
		{
			return true;
		}
	}

	return false;
}

void falco_ruleset::ruleset_filters::event_tags_for_ruleset(vector<bool> &event_tags)
{
	event_tags.assign(m_filter_by_event_tag.size(), false);

	for(uint32_t etag = 0; etag < m_filter_by_event_tag.size(); etag++)
	{
		list<filter_wrapper *> *filters = m_filter_by_event_tag[etag];
		if(filters)
		{
			event_tags[etag] = true;
		}
	}
}

void falco_ruleset::add(string &name,
			set<string> &tags,
			set<uint32_t> &event_tags,
			gen_event_filter *filter)
{
	filter_wrapper *wrap = new filter_wrapper();
	wrap->filter = filter;

	for(auto &etag : event_tags)
	{
		wrap->event_tags.resize(etag+1);
		wrap->event_tags[etag] = true;
	}

	m_filters.insert(pair<string,filter_wrapper *>(name, wrap));

	for(const auto &tag: tags)
	{
		auto it = m_filter_by_event_tag.lower_bound(tag);

		if(it == m_filter_by_event_tag.end() ||
		   it->first != tag)
		{
			it = m_filter_by_event_tag.emplace_hint(it,
							  make_pair(tag, list<filter_wrapper*>()));
		}

		it->second.push_back(wrap);
	}
}

void falco_ruleset::enable(const string &pattern, bool enabled, uint16_t ruleset)
{
	regex re(pattern);

	while (m_rulesets.size() < (size_t) ruleset + 1)
	{
		m_rulesets.push_back(new ruleset_filters());
	}

	for(const auto &val : m_filters)
	{
		if (regex_match(val.first, re))
		{
			if(enabled)
			{
				m_rulesets[ruleset]->add_filter(val.second);
			}
			else
			{
				m_rulesets[ruleset]->remove_filter(val.second);
			}
		}
	}
}

void falco_ruleset::enable_tags(const set<string> &tags, bool enabled, uint16_t ruleset)
{
	while (m_rulesets.size() < (size_t) ruleset + 1)
	{
		m_rulesets.push_back(new ruleset_filters());
	}

	for(const auto &tag : tags)
	{
		for(const auto &wrap : m_filter_by_event_tag[tag])
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

bool falco_ruleset::run(gen_event *evt, uint32_t etag, uint16_t ruleset)
{
	if(m_rulesets.size() < (size_t) ruleset + 1)
	{
		return false;
	}

	return m_rulesets[ruleset]->run(evt, etag);
}

void falco_ruleset::event_tags_for_ruleset(vector<bool> &evttypes, uint16_t ruleset)
{
	if(m_rulesets.size() < (size_t) ruleset + 1)
	{
		return;
	}

	return m_rulesets[ruleset]->event_tags_for_ruleset(evttypes);
}

falco_sinsp_ruleset::falco_sinsp_ruleset()
{
}

falco_sinsp_ruleset::~falco_sinsp_ruleset()
{
}

void falco_sinsp_ruleset::add(string &name,
			      set<uint32_t> &evttypes,
			      set<uint32_t> &syscalls,
			      set<string> &tags,
			      sinsp_filter* filter)
{
	set<uint32_t> event_tags;

	if(evttypes.size() + syscalls.size() == 0)
	{
		// If no evttypes or syscalls are specified, the filter is
		// enabled for all evttypes/syscalls.
		for(uint32_t i=0; i < PPM_EVENT_MAX; i++)
		{
			evttypes.insert(i);
		}

		for(uint32_t i=0; i < PPM_SC_MAX; i++)
		{
			syscalls.insert(i);
		}
	}

	for(auto evttype: evttypes)
	{
		event_tags.insert(evttype_to_event_tag(evttype));
	}

	for(auto syscallid: syscalls)
	{
		event_tags.insert(syscall_to_event_tag(syscallid));
	}

	falco_ruleset::add(name, tags, event_tags, (gen_event_filter *) filter);
}

bool falco_sinsp_ruleset::run(sinsp_evt *evt, uint16_t ruleset)
{
	uint32_t etag;

	uint16_t etype = evt->get_type();

	if(etype == PPME_GENERIC_E || etype == PPME_GENERIC_X)
	{
		sinsp_evt_param *parinfo = evt->get_param(0);
		uint16_t syscallid = *(uint16_t *)parinfo->m_val;

		etag = syscall_to_event_tag(syscallid);
	}
	else
	{
		etag = evttype_to_event_tag(etype);
	}

	return falco_ruleset::run((gen_event*) evt, etag, ruleset);
}

void falco_sinsp_ruleset::evttypes_for_ruleset(vector<bool> &evttypes, uint16_t ruleset)
{
	vector<bool> event_tags;

	event_tags_for_ruleset(event_tags, ruleset);

	evttypes.assign(PPM_EVENT_MAX+1, false);

	for(uint32_t etype = 0; etype < PPM_EVENT_MAX; etype++)
	{
		uint32_t etag = evttype_to_event_tag(etype);

		if(etag < event_tags.size() && event_tags[etag])
		{
			evttypes[etype] = true;
		}
	}
}

void falco_sinsp_ruleset::syscalls_for_ruleset(vector<bool> &syscalls, uint16_t ruleset)
{
	vector<bool> event_tags;

	event_tags_for_ruleset(event_tags, ruleset);

	syscalls.assign(PPM_EVENT_MAX+1, false);

	for(uint32_t syscallid = 0; syscallid < PPM_SC_MAX; syscallid++)
	{
		uint32_t etag = evttype_to_event_tag(syscallid);

		if(etag < event_tags.size() && event_tags[etag])
		{
			syscalls[syscallid] = true;
		}
	}
}

uint32_t falco_sinsp_ruleset::evttype_to_event_tag(uint32_t evttype)
{
	return evttype;
}

uint32_t falco_sinsp_ruleset::syscall_to_event_tag(uint32_t syscallid)
{
	return PPM_EVENT_MAX+1+syscallid;
}

