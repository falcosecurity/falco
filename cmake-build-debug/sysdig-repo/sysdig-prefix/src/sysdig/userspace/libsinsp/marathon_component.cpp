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
// marathon_component.cpp
//

#include "marathon_component.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <iostream>

//
// component
//

marathon_component::task_app_map_t marathon_component::m_task_app_cache;

const marathon_component::component_map marathon_component::list =
{
	{ marathon_component::MARATHON_GROUP, "group" },
	{ marathon_component::MARATHON_APP,   "app"   }
};

marathon_component::marathon_component(type t, const std::string& id) : 
	m_type(t),
	m_id(id)
{
	component_map::const_iterator it = list.find(t);
	if(it == list.end())
	{
		throw sinsp_exception("Invalid Marathon component type: " + std::to_string(t));
	}

	if(m_id.empty())
	{
		throw sinsp_exception("Marathon " + it->second + " ID cannot be empty");
	}
}

marathon_component::marathon_component(const marathon_component& other): m_type(other.m_type),
	m_id(other.m_id)
{
}

marathon_component::marathon_component(marathon_component&& other):  m_type(other.m_type),
	m_id(std::move(other.m_id))
{
}

marathon_component& marathon_component::operator=(const marathon_component& other)
{
	m_type = other.m_type;
	m_id = other.m_id;
	return *this;
}

marathon_component& marathon_component::operator=(const marathon_component&& other)
{
	m_type = other.m_type;
	m_id = std::move(other.m_id);
	return *this;
}

std::string marathon_component::get_type_name(type t)
{
	component_map::const_iterator it = list.find(t);
	if(it != list.end())
	{
		return it->second;
	}

	std::ostringstream os;
	os << "Unknown component type " << static_cast<int>(t);
	throw sinsp_exception(os.str().c_str());
}

marathon_component::type marathon_component::get_type(const std::string& name)
{
	if(name == "group")
	{
		return MARATHON_GROUP;
	}
	else if(name == "app")
	{
		return MARATHON_APP;
	}

	std::ostringstream os;
	os << "Unknown component name " << name;
	throw sinsp_exception(os.str().c_str());
}

void marathon_component::cache_task_app(const std::string& task_id, app_ptr_t app)
{
	m_task_app_cache[task_id] = app;
}

void marathon_component::uncache_task_app(const std::string& task_id)
{
	m_task_app_cache.erase(task_id);
}

marathon_component::app_ptr_t marathon_component::get_cached_app(const std::string& task_id)
{
	task_app_map_t::iterator it = m_task_app_cache.find(task_id);
	if(it != m_task_app_cache.end())
	{
		return it->second;
	}
	return 0;
}

//
// app
//

marathon_app::marathon_app(const std::string& id) :
	marathon_component(marathon_component::MARATHON_APP, id)
{
}

marathon_app::~marathon_app()
{
}

void marathon_app::add_task(mesos_framework::task_ptr_t ptask)
{
	if(ptask)
	{
		const std::string& task_id = ptask->get_uid();
		ptask->set_marathon_app_id(get_id());
		for(auto& task : m_tasks)
		{
			if(task == task_id) { return; }
		}
		m_tasks.push_back(task_id);
		cache_task_app(task_id, shared_from_this());
	}
	else
	{
		g_logger.log("Attempt to add null task to app [" + get_id() + ']', sinsp_logger::SEV_WARNING);
	}
}

bool marathon_app::remove_task(const std::string& task_id)
{
	for(auto it = m_tasks.begin(); it != m_tasks.end(); ++it)
	{
		if(task_id == *it)
		{
			m_tasks.erase(it);
			uncache_task_app(task_id);
			return true;
		}
	}
	g_logger.log("Task [" + task_id + "] not found in app [" + get_id() + ']', sinsp_logger::SEV_WARNING);
	return false;
}

bool marathon_app::has_task(const std::string& task_id)
{
	for(auto it = m_tasks.begin(); it != m_tasks.end(); ++it)
	{
		if(task_id == *it)
		{
			return true;
		}
	}
	return false;
}

std::string marathon_app::get_group_id() const
{
	return get_group_id(get_id());
}

std::string marathon_app::get_group_id(const std::string& app_id)
{
	std::string group_id;
	std::string::size_type pos = app_id.rfind('/');
	if(pos != std::string::npos && app_id.length() > pos)
	{
		pos += (pos == 0) ? 1 : 0;
		group_id = app_id.substr(0, pos);
	}
	return group_id;
}

void marathon_app::set_labels(const Json::Value& labels)
{
	m_labels.clear();
	Json::Value::Members members = labels.getMemberNames();
	for(const auto& member : members)
	{
		if(labels[member].isConvertibleTo(Json::ValueType::stringValue))
		{
			m_labels.push_back({member, labels[member].asString()});
		}
	}
}

mesos_pair_t marathon_app::get_label(const std::string& key) const
{
	for(const auto& label : m_labels)
	{
		if(label.first == key)
		{
			return label;
		}
	}
	return mesos_pair_t();
}

//
// group
//

marathon_group::marathon_group(const std::string& id, const std::string& framework_id) :
	marathon_component(marathon_component::MARATHON_GROUP, id),
	m_framework_id(framework_id)
{
}

marathon_group::app_ptr_t marathon_group::get_app(const std::string& id)
{
	for(const auto& app : m_apps)
	{
		if(app.second && app.second->get_id() == id)
		{
			return app.second;
		}
	}
	return 0;
}

marathon_group::ptr_t marathon_group::get_group(const std::string& group_id)
{
	if(group_id == get_id())
	{
		return shared_from_this();
	}

	marathon_groups::iterator it = m_groups.find(group_id);
	if(it != m_groups.end())
	{
		return it->second;
	}
	else
	{
		for(auto group : m_groups)
		{
			if(ptr_t p_group = group.second->get_group(group_id))
			{
				return p_group;
			}
		}
	}
	return 0;
}

bool marathon_group::remove(const std::string& id)
{
	if(id == get_id())
	{
		throw sinsp_exception("Invalid access - group can not remove itself.");
	}

	if(ptr_t group = get_parent(id))
	{
		return group->remove_group(id);
	}

	return false;
}

marathon_group::ptr_t marathon_group::get_parent(const std::string& id)
{
	marathon_groups::iterator it = m_groups.find(id);
	if(it != m_groups.end())
	{
		return shared_from_this();
	}
	else
	{
		for(auto group : m_groups)
		{
			if(group.second->get_group(id))
			{
				return group.second;
			}
		}
	}
	return 0;
}

bool marathon_group::remove_group(const std::string& id)
{
	marathon_groups::iterator it = m_groups.find(id);
	if(it != m_groups.end())
	{
		m_groups.erase(it);
		return true;
	}
	return false;
}

bool marathon_group::remove_app(const std::string& id)
{
	auto it = m_apps.find(id);
	if(it != m_apps.end())
	{
		m_apps.erase(it);
		return true;
	}
	return false;
}

bool marathon_group::remove_task(const std::string& id)
{
	for(auto& app : m_apps)
	{
		if(app.second && app.second->remove_task(id))
		{
			return true;
		}
	}
	return false;
}

marathon_group::app_ptr_t marathon_group::get_app(mesos_task::ptr_t task) const
{
	return get_cached_app(task->get_uid());
}

marathon_group::ptr_t marathon_group::get_group(mesos_task::ptr_t task)
{
	for(const auto& app : m_apps)
	{
		if(app.second && app.second->has_task(task->get_uid()))
		{
			return shared_from_this();
		}
	}
	for(const auto& group : m_groups)
	{
		app_ptr_t app = group.second->get_app(task);
		if(app)
		{
			return group.second;
		}
	}
	return 0;
}

void marathon_group::print(int indent) const
{
	for(int j = 0; j < indent; ++j)
	{
		std::cout << " ";
	}
	std::cout << get_id() << std::endl;
	for(auto& group : m_groups)
	{
		group.second->print(indent+2);
	}
}


