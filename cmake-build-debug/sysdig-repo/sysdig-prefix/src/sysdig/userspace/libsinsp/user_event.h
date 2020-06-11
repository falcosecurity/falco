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

#pragma once

#include "sinsp_int.h"

#include <memory>
#include <mutex>
#include <algorithm>
#include <string>
#include <set>
#include <unordered_map>
// c++ std regex is buggy on g++ 4.8
// so we use POSIX regex on non-windows
#ifndef _WIN32
#include <regex.h>
#else
#include <regex>
#endif

#include "sinsp_int.h"

//
// scope utilities
//
class event_scope
{
public:
	typedef std::vector<std::string> string_list_t;

	static const std::string SCOPE_OP_AND;
	static const string_list_t RESERVED_STRINGS;
	static const string_list_t REPLACEMENT_STRINGS;
	static const std::string KEY_FORMAT;

	event_scope(const std::string& key = "", const std::string& value = "");

	bool add(const std::string& key, const std::string& value, const std::string& op = SCOPE_OP_AND);

	const std::string& get() const;
	std::string& get_ref();

	void clear();

	// utility function to check that a scope entry key is valid;
	// valid entries match KEY_FORMAT regular expression
	static bool check_key_format(const std::string& key);

private:

	// utility function to replace RESERVED_STRINGS with their
	// counterparts in REPLACEMENT_STRINGS
	static string& replace(std::string& scope);
#ifndef _WIN32
	static void regex_error(const std::string& call, size_t ret, regex_t* preg, const std::string& str);
#endif
	std::string m_scope;
};

inline const std::string& event_scope::get() const
{
	if(m_scope.empty())
	{
		g_logger.log("Scope is empty--at least one key/value pair should be present",
			     sinsp_logger::SEV_WARNING);
	}
	return m_scope;
}

inline std::string& event_scope::get_ref()
{
	if(m_scope.empty())
	{
		g_logger.log("Scope is empty--at least one key/value pair should be present",
			     sinsp_logger::SEV_WARNING);
	}

	return m_scope;
}

inline void event_scope::clear()
{
	m_scope.clear();
}


//
// user-configured event meta
//
class user_event_meta_t
{
public:
	typedef std::set<std::string, ci_compare> type_list_t;

	static const std::string PERMIT_ALL;

	user_event_meta_t() {};
	~user_event_meta_t() {};

	user_event_meta_t(const std::string& kind, const type_list_t& types);
	user_event_meta_t(std::string&& kind, type_list_t&& types);
	user_event_meta_t(const user_event_meta_t& other);
	user_event_meta_t(user_event_meta_t&& other);

	user_event_meta_t& operator = (const user_event_meta_t& other);
	user_event_meta_t& operator = (user_event_meta_t&& other);
	bool operator < (const user_event_meta_t& other) const;

	const std::string& kind() const;
	const type_list_t& types() const;
	bool has_type(const std::string& type) const;
	bool any_type() const;
	bool is_kind(const std::string& kind) const;
	bool any_kind() const;

private:
	std::string m_kind;
	type_list_t m_types;
};

inline bool user_event_meta_t::operator < (const user_event_meta_t& other) const
{
#ifndef _WIN32
	return strcasecmp(m_kind.c_str(), other.m_kind.c_str()) < 0;
#else
	return lstrcmpiA(m_kind.c_str(), other.m_kind.c_str()) < 0;
#endif // _WIN32
}

inline const std::string& user_event_meta_t::kind() const
{
	return m_kind;
}

inline const user_event_meta_t::type_list_t& user_event_meta_t::types() const
{
	return m_types;
}

inline bool user_event_meta_t::has_type(const std::string& type) const
{
	return m_types.find(type) != m_types.end() || any_type();
}

inline bool user_event_meta_t::any_type() const
{
	return m_types.find(PERMIT_ALL) != m_types.end();
}

inline bool user_event_meta_t::is_kind(const std::string& kind) const
{
#ifndef _WIN32
	return (strcasecmp(m_kind.c_str(), kind.c_str()) == 0) || any_kind();
#else
	return lstrcmpiA(m_kind.c_str(), kind.c_str()) < 0;
#endif // _WIN32
}

inline bool user_event_meta_t::any_kind() const
{
#ifndef _WIN32
	return strcasecmp(m_kind.c_str(), PERMIT_ALL.c_str()) == 0;
#else
	return lstrcmpiA(m_kind.c_str(), PERMIT_ALL.c_str()) < 0;
#endif // _WIN32
}


//
// user-configured-event filter
//
class user_event_filter_t
{
public:
	typedef std::set<user_event_meta_t> list_t;
	typedef std::shared_ptr<user_event_filter_t> ptr_t;

	user_event_filter_t();
	user_event_filter_t(const list_t& list);
	user_event_filter_t(list_t&& list);

	void add(const user_event_meta_t& evt);
	void add(user_event_meta_t&& evt);
	bool has(const std::string& evt_kind) const;
	bool has(const std::string& evt_kind, const std::string& evt_type) const;
	list_t::const_iterator get(const std::string& evt_kind) const;
	void remove(const user_event_meta_t& evt);
	void remove(const std::string& kind);
	void clear();
	bool allows(const user_event_meta_t& evt) const;
	bool allows_all(const std::string& kind) const;
	bool allows_all() const;

	std::string to_string() const;

private:
	static bool ci_compare_str(const std::string& a, const std::string& b);

	// if the filter entry of the requested kind is found, returns const iterator pointing to it;
	// if "any event" entry is found, iterator pointing to it is returned; otherwise, the iterator
	// pointing to the end of the filter list is returned (indicating the event kind was not found)
	list_t::const_iterator get_meta(const std::string& evt_kind) const;

	bool handle_all(user_event_meta_t&& evt);

	list_t m_list;
};

inline void user_event_filter_t::clear()
{
	m_list.clear();
}

inline bool user_event_filter_t::ci_compare_str(const std::string& a, const std::string& b)
{
#ifndef _WIN32
	return strcasecmp(a.c_str(), b.c_str()) == 0;
#else
	return lstrcmpiA(a.c_str(), b.c_str()) == 0;
#endif // _WIN32
}

inline bool user_event_filter_t::has(const std::string& evt_kind) const
{
	return get(evt_kind) != m_list.end();
}

inline bool user_event_filter_t:: allows_all(const std::string& kind) const
{
	return allows(user_event_meta_t(kind, {user_event_meta_t::PERMIT_ALL}));
}

inline bool user_event_filter_t::allows_all() const
{
	return get(user_event_meta_t::PERMIT_ALL) != m_list.end();
}

//
// Wrapper class for user-configured events
//
class sinsp_user_event
{
public:
	typedef std::unordered_map<std::string, std::string> tag_map_t;
	static const uint32_t UNKNOWN_SEVERITY = static_cast<uint32_t>(~0);

	sinsp_user_event(const sinsp_user_event&) = delete;
	sinsp_user_event& operator=(const sinsp_user_event& other) = delete;

	sinsp_user_event();

	sinsp_user_event(uint64_t epoch_time_s, std::string&& name, std::string&& desc,
		std::string&& scope, tag_map_t&& tags, uint32_t sev);

	sinsp_user_event(sinsp_user_event&& other);

	sinsp_user_event& operator=(sinsp_user_event&& other);

	uint64_t epoch_time_s() const;
	const std::string& name() const;
	const std::string& description() const;
	uint32_t severity() const;
	const std::string& scope() const;
	const tag_map_t& tags() const;

	/**
	 * \brief Format the event as a YAML-like human readable string
	 * @return the formatted string
	 *
	 * Note: While the format looks superficially similar to YAML, it's not.
	 * This method does not generate valid YAML, especially when characters
	 * like quotes, backslashes or newlines are found in any of the fields
	 */
	std::string to_string();

	static void emit_event_overflow(const std::string& component,
									const std::string& machine_id,
									const std::string& source = "sysdig-agent");
	static size_t max_events_per_cycle();

private:
	uint64_t    m_epoch_time_s;
	std::string m_name;
	std::string m_description;
	uint32_t    m_severity;
	std::string m_scope;
	tag_map_t   m_tags;
};

inline uint64_t sinsp_user_event::epoch_time_s() const
{
	return m_epoch_time_s;
}

inline const std::string& sinsp_user_event::name() const
{
	return m_name;
}

inline const std::string& sinsp_user_event::description() const
{
	return m_description;
}

inline uint32_t sinsp_user_event::severity() const
{
	return m_severity;
}

inline const std::string& sinsp_user_event::scope() const
{
	return m_scope;
}

inline const sinsp_user_event::tag_map_t& sinsp_user_event::tags() const
{
	return m_tags;
}

inline size_t sinsp_user_event::max_events_per_cycle()
{
	return 100u; // TODO: move this value to config?
}

//
// User-configured events queue
//
class user_event_queue
{
public:
	typedef std::shared_ptr<user_event_queue> ptr_t;
	typedef std::deque<sinsp_user_event> type_t;

	void add(sinsp_user_event&& evt);
	bool get(sinsp_user_event& evt);
	type_t::size_type count() const;

private:
	type_t m_queue;
	mutable std::mutex m_mutex;
};

inline void user_event_queue::add(sinsp_user_event&& evt)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_queue.emplace_back(std::move(evt));
}

inline bool user_event_queue::get(sinsp_user_event& evt)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	if(!m_queue.size())
	{
		return false;
	}
	evt = std::move(m_queue.front());
	m_queue.pop_front();
	return true;
}

inline user_event_queue::type_t::size_type user_event_queue::count() const
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_queue.size();
}
