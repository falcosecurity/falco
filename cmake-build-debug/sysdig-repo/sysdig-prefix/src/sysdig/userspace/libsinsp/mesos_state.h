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
//
// mesos_state_t.h
//
// mesos state abstraction
//

#pragma once

#include "mesos_component.h"
#include "marathon_component.h"
#include "json/json.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "json_error_log.h"
#include <vector>
#include <map>
#include <unordered_map>
#include <algorithm>

//
// state
//

class mesos_state_t
{
public:
	typedef std::shared_ptr<Json::Value> json_ptr_t;

#ifdef HAS_CAPTURE
	struct capture
	{
		enum type_t
		{
			MESOS_STATE = 0,
			MARATHON_GROUPS = 1,
			MARATHON_APPS = 2
		};

		capture(type_t type, std::string&& data):
				m_type(type),
				m_data(std::move(data))
		{
		}

		std::string to_string()
		{
			m_data.erase(std::remove_if(m_data.begin(), m_data.end(), [](char c) { return c == '\r' || c == '\n'; }));
			std::ostringstream os;
			switch(m_type)
			{
				case MESOS_STATE:
					os << "{\"mesos_state\":" << m_data << '}' << std::flush;
					break;
				case MARATHON_GROUPS:
					os << "{\"marathon_groups\":" << m_data << '}' << std::flush;
					break;
				case MARATHON_APPS:
					os << "{\"marathon_apps\":" << m_data << '}' << std::flush;
					break;
			}
			return os.str();
		}

		type_t      m_type;
		std::string m_data;
	};
	typedef std::deque<capture> capture_list;

	const capture_list& get_capture_events() const
	{
		return m_capture;
	}

	std::string dequeue_capture_event()
	{
		std::string ret;
		if(m_capture.size())
		{
			ret = m_capture.front().to_string();
			m_capture.pop_front();
		}
		return ret;
	}

	void enqueue_capture_event(capture::type_t type, std::string&& data)
	{
		if(m_is_captured)
		{
			m_capture.emplace_back(capture(type, std::move(data)));
		}
	}

	bool is_captured() const
	{
		return m_is_captured;
	}

	void capture_groups(const Json::Value& root, const std::string& framework_id, Json::Value& capt, bool capture_fw = false);
	void capture_apps(const Json::Value& root, const std::string& framework_id);
#endif // HAS_CAPTURE

	mesos_state_t(bool is_captured = false, bool verbose = false);

	//
	// frameworks
	//
	const mesos_frameworks& get_frameworks() const;
	mesos_frameworks& get_frameworks();
	const mesos_framework& get_framework(const std::string& framework_uid) const;
	mesos_framework& get_framework(const std::string& framework_uid);
	void push_framework(const mesos_framework& framework);
	void emplace_framework(mesos_framework&& framework);
	void remove_framework(const std::string& framework_uid);
	void remove_framework(const Json::Value& framework);
	const mesos_framework* get_framework_for_task(const std::string& task_id) const;

	//
	// tasks
	//
	std::unordered_set<std::string> get_all_task_ids() const;
	const mesos_framework::task_map& get_tasks(const std::string& framework_uid) const;
	mesos_framework::task_map& get_tasks(const std::string& framework_uid);
	mesos_framework::task_ptr_t get_task(const std::string& uid) const;
	void add_or_replace_task(mesos_framework& framework, mesos_task::ptr_t task);
	void remove_task(mesos_framework& framework, const std::string& uid);

	//
	// slaves
	//
	const mesos_slaves& get_slaves() const;
	mesos_slaves& get_slaves();
	const mesos_slave& get_slave(const std::string& slave_uid) const;
	mesos_slave& get_slave(const std::string& slave_uid);
	void push_slave(const mesos_slave& slave);
	void emplace_slave(mesos_slave&& slave);

	//
	// Marathon
	//

	void set_marathon_uri(const std::string& uri);
	const std::string& get_marathon_uri() const;

	//
	// Marathon apps
	//
	void parse_apps(Json::Value&& root, const std::string& framework_id);
	void parse_apps(json_ptr_t json, const std::string& framework_id);
	marathon_app::ptr_t get_app(const std::string& app_id);
	marathon_group::app_ptr_t add_or_replace_app(const std::string& id,
												const std::string& group,
												const std::string& task = "");
	bool remove_app(const std::string& id);
	void add_task_to_app(marathon_group::app_ptr_t app, const std::string& task_id);
	marathon_app::ptr_t get_app(mesos_task::ptr_t task) const;

	//
	// Marathon groups
	//
	bool parse_groups(Json::Value&& root, const std::string& framework_id);
	bool parse_groups(json_ptr_t json, const std::string& framework_id);
	const marathon_groups& get_groups() const;
	marathon_groups& get_groups();
	marathon_group::ptr_t get_group(const std::string& group_id);
	marathon_group::ptr_t get_group(mesos_task::ptr_t task) const;
	marathon_group::ptr_t add_or_replace_group(marathon_group::ptr_t group, marathon_group::ptr_t to_group = 0);
	marathon_group::ptr_t get_app_group(const std::string& app_id);
	void erase_groups(const std::string& framework_id);
	void print_groups() const;

	//
	// state
	//
	void clear_mesos();
	void clear_marathon();
	bool has_data() const;

private:
	marathon_group::ptr_t add_group(const Json::Value& group, marathon_group::ptr_t to_group, const std::string& framework_id);
	bool handle_groups(const Json::Value& groups, marathon_group::ptr_t p_groups, const std::string& framework_id);
	marathon_app::ptr_t add_app(const Json::Value& app, const std::string& framework_id);

	mesos_frameworks m_frameworks;
	std::string      m_marathon_uri;
	mesos_slaves     m_slaves;
	marathon_groups  m_groups;
	bool             m_verbose;
#ifdef HAS_CAPTURE
	bool             m_is_captured;
	capture_list     m_capture;
#endif // HAS_CAPTURE

	typedef std::unordered_map<std::string, mesos_framework*> task_framework_map_t;
	task_framework_map_t m_task_framework_cache;
};

//
// frameworks
//

inline const mesos_frameworks& mesos_state_t::get_frameworks() const
{
	return m_frameworks;
}

inline mesos_frameworks& mesos_state_t::get_frameworks()
{
	return m_frameworks;
}

inline const mesos_framework& mesos_state_t::get_framework(const std::string& framework_uid) const
{
	for(const auto& framework : m_frameworks)
	{
		if(framework.get_uid() == framework_uid)
		{
			return framework;
		}
	}
	throw sinsp_exception("Framework not found: " + framework_uid);
}

inline mesos_framework& mesos_state_t::get_framework(const std::string& framework_uid)
{
	for(auto& framework : m_frameworks)
	{
		if(framework.get_uid() == framework_uid)
		{
			return framework;
		}
	}
	throw sinsp_exception("Framework not found: " + framework_uid);
}

inline void mesos_state_t::push_framework(const mesos_framework& framework)
{
	for(mesos_frameworks::iterator it = m_frameworks.begin(); it != m_frameworks.end();)
	{
		if(it->get_uid() == framework.get_uid())
		{
			it = m_frameworks.erase(it);
		}
		else { ++it; }
	}
	m_frameworks.push_back(framework);
}

inline void mesos_state_t::emplace_framework(mesos_framework&& framework)
{
	for(mesos_frameworks::iterator it = m_frameworks.begin(); it != m_frameworks.end();)
	{
		if(it->get_uid() == framework.get_uid())
		{
			it = m_frameworks.erase(it);
		}
		else { ++it; }
	}
	m_frameworks.emplace_back(std::move(framework));
}

inline void mesos_state_t::remove_framework(const Json::Value& framework)
{
	const Json::Value& id = framework["id"];
	if(!id.isNull() && id.isString())
	{
		remove_framework(id.asString());
	}
}

inline const mesos_framework* mesos_state_t::get_framework_for_task(const std::string& task_id) const
{
	task_framework_map_t::const_iterator it = m_task_framework_cache.find(task_id);
	if(it != m_task_framework_cache.end())
	{
		return it->second;
	}
	return 0;
}

inline void mesos_state_t::remove_framework(const std::string& framework_uid)
{
	for(mesos_frameworks::iterator it = m_frameworks.begin(); it != m_frameworks.end(); ++it)
	{
		if(it->get_uid() == framework_uid)
		{
			for(auto& task : it->get_tasks())
			{
				m_task_framework_cache.erase(task.first);
			}
			m_frameworks.erase(it);
			return;
		}
	}
}

//
// tasks
//
inline void mesos_state_t::add_or_replace_task(mesos_framework& framework, mesos_task::ptr_t task)
{
	if(task)
	{
		framework.add_or_replace_task(task);
		m_task_framework_cache[task->get_uid()] = &framework;
	}
}

inline void mesos_state_t::remove_task(mesos_framework& framework, const std::string& uid)
{
	mesos_task::ptr_t task = framework.get_task(uid);
	if(task)
	{
		std::string app_id = task->get_marathon_app_id();
		if(!app_id.empty())
		{
			marathon_group::ptr_t group = get_app_group(app_id);
			if(group)
			{
				if(!group->remove_task(uid))
				{
					std::string errstr = "Task [" + uid + "] not found in Marathon app [" + app_id + ']';
					g_logger.log(errstr,
						     sinsp_logger::SEV_ERROR);
					g_json_error_log.log(uid, errstr, sinsp_utils::get_current_time_ns(), "remove-task");
				}
			}
			else
			{
				std::string errstr = "Group not found for Marathon app [" + app_id + "] while trying to remove task [" + uid + ']';
				g_logger.log(errstr,
					     sinsp_logger::SEV_ERROR);
				g_json_error_log.log(app_id, errstr, sinsp_utils::get_current_time_ns(), "remove-task");
			}
		}
		else
		{
			g_logger.log("Task [" + uid + "] has no Marathon app ID.", sinsp_logger::SEV_WARNING);
		}
	}
	else
	{
		g_logger.log("Task [" + uid + "] not found in framework [" + framework.get_uid() + ']', sinsp_logger::SEV_WARNING);
	}
	framework.remove_task(uid);
	m_task_framework_cache.erase(uid);
}

//
// slaves
//

inline const mesos_slaves& mesos_state_t::get_slaves() const
{
	return m_slaves;
}

inline mesos_slaves& mesos_state_t::get_slaves()
{
	return m_slaves;
}

inline const mesos_slave& mesos_state_t::get_slave(const std::string& slave_uid) const
{
	for(const auto& slave : m_slaves)
	{
		if(slave.get_uid() == slave_uid)
		{
			return slave;
		}
	}
	throw sinsp_exception("Slave not found: " + slave_uid);
}

inline mesos_slave& mesos_state_t::get_slave(const std::string& slave_uid)
{
	for(auto& slave : m_slaves)
	{
		if(slave.get_uid() == slave_uid)
		{
			return slave;
		}
	}
	throw sinsp_exception("Slave not found: " + slave_uid);
}

inline void mesos_state_t::push_slave(const mesos_slave& slave)
{
	for(mesos_slaves::iterator it = m_slaves.begin(); it != m_slaves.end();)
	{
		if(it->get_uid() == slave.get_uid())
		{
			it = m_slaves.erase(it);
		}
		else { ++it; }
	}
	m_slaves.push_back(slave);
}

inline void mesos_state_t::emplace_slave(mesos_slave&& slave)
{
	for(mesos_slaves::iterator it = m_slaves.begin(); it != m_slaves.end();)
	{
		if(it->get_uid() == slave.get_uid())
		{
			it = m_slaves.erase(it);
		}
		else { ++it; }
	}
	m_slaves.emplace_back(std::move(slave));
}

//
// Marathon
//

inline void mesos_state_t::set_marathon_uri(const std::string& uri)
{
	m_marathon_uri = uri;
}

inline const std::string& mesos_state_t::get_marathon_uri() const
{
	return m_marathon_uri;
}

//
// apps
//

//
// groups
//

inline const marathon_groups& mesos_state_t::get_groups() const
{
	return m_groups;
}

inline marathon_groups& mesos_state_t::get_groups()
{
	return m_groups;
}

//
// state
//

inline void mesos_state_t::clear_mesos()
{
	m_frameworks.clear();
	m_slaves.clear();
}

inline void mesos_state_t::clear_marathon()
{
	m_groups.clear();
}

inline bool mesos_state_t::has_data() const
{
	return m_frameworks.size() > 0 && m_slaves.size() > 0;
}
