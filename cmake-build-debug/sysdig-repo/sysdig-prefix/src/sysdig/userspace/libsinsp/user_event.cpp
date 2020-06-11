/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

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

#include "sinsp.h"
#include "sinsp_int.h"
#include "user_event.h"
#include "user_event_logger.h"

//
// event_scope
//

const std::string event_scope::SCOPE_OP_AND = "and";

// these string lists contain reserved strings; some of the reserved
// strings are escaped and mandatory to be first in RESERVED_STRINGS
// and have their escaped counterparts in the REPLACEMENT_STRINGS,
// in the same order as they appear in RESERVED_STRINGS
const event_scope::string_list_t event_scope::RESERVED_STRINGS =
	{"'"};
const event_scope::string_list_t event_scope::REPLACEMENT_STRINGS =
	{"\\'"};

// scope key name format regex
#ifndef _WIN32
const std::string event_scope::KEY_FORMAT = "[a-zA-Z0-9_/\\.-]*";
#else
const std::string event_scope::KEY_FORMAT = "^[a-zA-Z0-9_/\\.-]*$";
#endif // _WIN32

event_scope::event_scope(const std::string& key, const std::string& value)
{
	if(!key.empty() && !value.empty())
	{
		add(key, value, "");
	}
}

bool event_scope::add(const std::string& key, const std::string& value, const std::string& op)
{
	if(check_key_format(key))
	{
		std::string k(key);
		std::string o(!m_scope.empty() ? op : "");
		std::string v(value);
		replace(v);
		if(!v.empty())
		{
			if(!o.empty())
			{
				m_scope.append(1, ' ').append(trim(o)).append(1, ' ');
			}
			m_scope.append(trim(k)).append("='").append(trim(v)).append(1, 0x27);
			return true;
		}
	}
	else
	{
		g_logger.log("Scope key is invalid: [" + key + "], entry will not be added to scope.",
					 sinsp_logger::SEV_WARNING);
	}
	return false;
}

string& event_scope::replace(std::string& value)
{
	ASSERT(RESERVED_STRINGS.size() == REPLACEMENT_STRINGS.size());

	string_list_t::const_iterator res_it = RESERVED_STRINGS.cbegin();
	string_list_t::const_iterator res_end = RESERVED_STRINGS.cend();
	string_list_t::const_iterator rep_it = REPLACEMENT_STRINGS.cbegin();
	string_list_t::const_iterator rep_end = REPLACEMENT_STRINGS.cend();
	for(; res_it != res_end && rep_it != rep_end; ++res_it, ++rep_it)
	{
		replace_in_place(value, *res_it, *rep_it);
	}

	return value;
}

#ifndef _WIN32
void event_scope::regex_error(const std::string& call, size_t ret, regex_t* preg, const std::string& str)
{
	if(!preg) { return; }
	char errbuf[256] = {0};
	if(regerror(ret, preg, errbuf, 256))
	{
		g_logger.log(call + "() error: " + errbuf, sinsp_logger::SEV_WARNING);
	}
	else
	{
		g_logger.log("Can't obtain " + call + "() [" + str + "] error.", sinsp_logger::SEV_WARNING);
	}
}

bool event_scope::check_key_format(const std::string& key)
{

	if(key.empty()) { return false; }
	bool result = false;
	std::string exp(KEY_FORMAT);
	regex_t reg = {0};
	size_t ret = regcomp(&reg, exp.c_str(), REG_EXTENDED);
	if(0 == ret)
	{
		regmatch_t rm = {0};
		ret = regexec(&reg, key.c_str(), 1, &rm, 0);
		if(0 == ret)
		{
			if((rm.rm_eo - rm.rm_so) == static_cast<regoff_t>(key.length()))
			{
				result = true;
			}
		}
		else { regex_error("regexec", ret, &reg, key); }
	}
	else { regex_error("regcomp", ret, &reg, exp); }
	regfree(&reg);
	return result;
}

#else

bool event_scope::check_key_format(const std::string& key)
{
	static const std::regex r(KEY_FORMAT);
	if (std::regex_match(key, r)) { return true; }
	return false;
}

#endif // _WIN32

//
// user_event_meta_t
//
const std::string user_event_meta_t::PERMIT_ALL = "all";

user_event_meta_t::user_event_meta_t(const std::string& kind, const type_list_t& types):
	m_kind(kind), m_types(types)
{
}

user_event_meta_t::user_event_meta_t(std::string&& kind, type_list_t&& types):
	m_kind(std::move(kind)), m_types(std::move(types))
{
}

user_event_meta_t::user_event_meta_t(const user_event_meta_t& other):
	m_kind(other.m_kind), m_types(other.m_types)
{
}

user_event_meta_t::user_event_meta_t(user_event_meta_t&& other):
	m_kind(std::move(other.m_kind)), m_types(std::move(other.m_types))
{
	other.m_kind.clear();
	other.m_types.clear();
}

user_event_meta_t& user_event_meta_t::operator = (const user_event_meta_t& other)
{
	if(&other != this)
	{
		m_kind = other.m_kind;
		m_types = other.m_types;
	}
	return *this;
}

user_event_meta_t& user_event_meta_t::operator = (user_event_meta_t&& other)
{
	if(&other != this)
	{
		m_kind = std::move(other.m_kind);
		m_types = std::move(other.m_types);
		other.m_kind.clear();
		other.m_types.clear();
	}
	return *this;
}

//
// user_event_filter_t
//
user_event_filter_t::user_event_filter_t()
{
}

user_event_filter_t::user_event_filter_t(const list_t& list): m_list(list)
{
}

user_event_filter_t::user_event_filter_t(list_t&& list): m_list(std::move(list))
{
}

void user_event_filter_t::add(const user_event_meta_t& evt)
{
	if(handle_all(user_event_meta_t(evt)))
	{
		return;
	}
	if(get_meta(evt.kind()) == m_list.end())
	{
		m_list.insert(evt);
	}
}

void user_event_filter_t::add(user_event_meta_t&& evt)
{
	if(handle_all(user_event_meta_t(evt)))
	{
		return;
	}
	if(get_meta(evt.kind()) == m_list.end())
	{
		m_list.emplace(std::move(evt));
	}
}

bool user_event_filter_t::handle_all(user_event_meta_t&& evt)
{
	if(ci_compare_str(evt.kind(), user_event_meta_t::PERMIT_ALL))
	{
		m_list.clear();
		m_list.emplace(std::move(evt));
		return true;
	}
	user_event_meta_t loc_evt(evt);
	list_t::iterator it = m_list.find(loc_evt);
	if(it != m_list.end())
	{
		if(it->types().find(user_event_meta_t::PERMIT_ALL) != it->types().end())
		{
			m_list.erase(it);
			m_list.insert(loc_evt);
			return true;
		}
	}
	return false;
}

void user_event_filter_t::remove(const user_event_meta_t& evt)
{
	m_list.erase(evt);
}

void user_event_filter_t::remove(const std::string& kind)
{
	user_event_meta_t::type_list_t types;
	user_event_meta_t evt(kind, types);
	remove(evt);
}

user_event_filter_t::list_t::const_iterator user_event_filter_t::get(const std::string& evt_kind) const
{
	list_t::const_iterator it = m_list.begin(), end = m_list.end();
	for(;it != end; ++it)
	{
		if(ci_compare_str(it->kind(), evt_kind)) { return it; }
	}
	return end;
}

bool user_event_filter_t::has(const std::string& evt_kind, const std::string& evt_type) const
{
	list_t::const_iterator it = get(evt_kind);
	if(it != m_list.end())
	{
		for(const auto& t : it->types())
		{
			if(ci_compare_str(t, evt_type))
			{
				return true;
			}
		}
	}
	return false;
}

bool user_event_filter_t::allows(const user_event_meta_t& evt) const
{
	list_t::const_iterator it = get_meta(evt.kind());
	if(it != m_list.end()) // this event kind is allowed
	{
		// check for "any event" type being allowed by this filter
		if(it->types().find(user_event_meta_t::PERMIT_ALL) != it->types().end())
		{
			return true;
		}
		// check if event has more types than this filter
		if(evt.types().size() > it->types().size())
		{
			return false;
		}
		// if all event types are present in this filter, event is allowed
		for(auto const& type : evt.types())
		{
			if(it->types().find(type) == it->types().end())
			{
				return false;
			}
		}
		return true;
	}
	return false;
}

user_event_filter_t::list_t::const_iterator user_event_filter_t::get_meta(const std::string& evt_kind) const
{
	list_t::const_iterator it = m_list.begin(), end = m_list.end();
	for(; it != end; ++it)
	{
		if(ci_compare_str(it->kind(), user_event_meta_t::PERMIT_ALL) || ci_compare_str(it->kind(),evt_kind))
		{
			return it;
		}
	}
	return end;
}

std::string user_event_filter_t::to_string() const
{
	std::string ret;
	for(const auto& evt : m_list)
	{
		if(evt.types().size())
		{
			ret.append(1, '\n').append(evt.kind()).append(1, ':');
			for(const auto& type : evt.types())
			{
				ret.append(type).append(", ");
			}
		}
	}
	return ret;
}

//
// sinsp_user_event
//

sinsp_user_event::sinsp_user_event() : m_epoch_time_s(0), m_severity(~0)
{
}

sinsp_user_event::sinsp_user_event(uint64_t epoch_time_s, string&& name, string&& desc,
	string&& scope, tag_map_t&& tags, uint32_t sev):
	m_epoch_time_s(epoch_time_s), m_name(std::move(name)), m_description(std::move(desc)),
	m_severity(sev), m_scope(std::move(scope)), m_tags(std::move(tags))
{
}

sinsp_user_event::sinsp_user_event(sinsp_user_event&& other):
	m_epoch_time_s(other.m_epoch_time_s),
	m_name(std::move(other.m_name)),
	m_description(std::move(other.m_description)),
	m_severity(other.m_severity),
	m_scope(std::move(other.m_scope)),
	m_tags(std::move(other.m_tags))
{
}

sinsp_user_event& sinsp_user_event::operator=(sinsp_user_event&& other)
{
	if(this != &other)
	{
		m_epoch_time_s = other.m_epoch_time_s;
		m_name = std::move(other.m_name);
		m_description = std::move(other.m_description);
		m_severity = other.m_severity;
		m_scope = std::move(other.m_scope);
		m_tags = std::move(other.m_tags);
	}

	return *this;
}

std::string sinsp_user_event::to_string()
{
	std::ostringstream ostr;
	ostr << "timestamp: " << m_epoch_time_s << '\n' <<
			"name: " << m_name << "\n"
			"description: " << m_description << "\"\n"
			"scope: " << m_scope << "\"\n";

	if(m_severity != UNKNOWN_SEVERITY)
	{
		ostr << "priority: " << m_severity << '\n';
	}

	if(m_tags.size())
	{
		ostr << "tags:";
		for(auto& tag : m_tags)
		{
			ostr << "\n  " << tag.first << ": " << tag.second;
		}
	}
	ostr << std::flush;
	return ostr.str();
}

void sinsp_user_event::emit_event_overflow(const std::string& component,
										   const std::string& machine_id,
										   const std::string& source)
{
	std::string event_name = component;
	event_name.append(" Event Limit Exceeded");
	std::ostringstream description;
	description << component << " event limit (" << max_events_per_cycle() <<
				" per second) exceeded. Excess events were discarded.";
	std::string scope;
	if(machine_id.length())
	{
		scope.append("host.mac='").append(machine_id).append("'");
	}
	tag_map_t tags{{"source", source}};

	auto evt = sinsp_user_event(
		get_epoch_utc_seconds_now(),
		std::move(event_name),
		description.str(),
		std::move(scope),
		std::move(tags),
		user_event_logger::SEV_EVT_WARNING);

	user_event_logger::log(evt, user_event_logger::SEV_EVT_WARNING);
}
