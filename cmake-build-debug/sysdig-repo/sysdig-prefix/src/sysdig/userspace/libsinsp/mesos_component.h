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
// mesos_component.h
//
// mesos components (frameworks, tasks, slaves)
// abstraction
//

#pragma once

#include "json/json.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>

typedef std::pair<std::string, std::string> mesos_pair_t;
typedef std::vector<mesos_pair_t>           mesos_pair_list;

// 
// component
//

class mesos_component
{
public:
	enum type
	{
		MESOS_FRAMEWORK,
		MESOS_TASK,
		MESOS_SLAVE
	};

	typedef std::pair<type, std::string> component_pair;
	typedef std::map<type, std::string> component_map;
	static const component_map list;

	mesos_component() = delete;

	mesos_component(type t, const std::string& name, const std::string& uid);

	mesos_component(const mesos_component& other);

	mesos_component(mesos_component&& other);

	mesos_component& operator=(const mesos_component& other);

	mesos_component& operator=(const mesos_component&& other);

	const std::string& get_name() const;

	void set_name(const std::string& name);

	const std::string& get_uid() const;

	void set_uid(const std::string& uid);

	mesos_pair_t* get_label(const mesos_pair_t& label);

	const mesos_pair_list& get_labels() const;

	void set_labels(mesos_pair_list&& labels);

	void add_labels(mesos_pair_list&& labels);

	void swap_labels(mesos_pair_list& new_labels);

	void push_label(const mesos_pair_t& label);

	void emplace_label(mesos_pair_t&& label);

	static const std::string& get_name(const component_pair& p);

	static std::string get_name(type t);

	static type get_type(const component_pair& p);

	static type get_type(const std::string& name);

private:
	type            m_type;
	std::string     m_name;
	std::string     m_uid;
	mesos_pair_list m_labels;
};


class mesos_framework;

//
// task
//

class mesos_task : public mesos_component
{
public:
	typedef std::shared_ptr<mesos_task> ptr_t;
	mesos_task(const std::string& name, const std::string& uid);

	mesos_task(const mesos_task& other);

	~mesos_task();

	mesos_task(mesos_task&& other);

	mesos_task& operator=(const mesos_task& other);

	mesos_task& operator=(const mesos_task&& other);

	void set_marathon_app_id(const std::string& app_id)
	{
		m_marathon_app_id = app_id;
	}

	const std::string& get_marathon_app_id() const
	{
		return m_marathon_app_id;
	}

	void set_slave_id(const std::string& slave_id)
	{
		m_slave_id = slave_id;
	}

	const std::string& get_slave_id() const
	{
		return m_slave_id;
	}

	static bool is_task_running(const Json::Value& task);
	static ptr_t make_task(const Json::Value& task);
	static void add_labels(ptr_t task, const Json::Value& t_val);

private:
	std::string m_marathon_app_id;
	std::string m_slave_id;
};

//
// framework
//

class mesos_framework : public mesos_component
{
public:
	static const std::string MARATHON_ROOT_NAME;

	typedef std::shared_ptr<mesos_framework> ptr_t;
	typedef mesos_task::ptr_t task_ptr_t;
	typedef std::unordered_map<std::string, task_ptr_t> task_map;

	mesos_framework(const std::string& name, const std::string& uid);

	~mesos_framework();

	bool has_task(const std::string& uid) const;

	task_ptr_t get_task(const std::string& id);

	void add_or_replace_task(std::shared_ptr<mesos_task> task);

	void remove_task(const std::string& uid);

	const task_map& get_tasks() const;

	task_map& get_tasks();

	static bool is_framework_active(const Json::Value& framework);
	static bool is_root_marathon(const std::string& name);

private:
	task_map m_tasks;
};


//
// slave
//

class mesos_slave : public mesos_component
{
public:
	mesos_slave(const std::string& name, const std::string& uid);

private:
};

typedef std::vector<mesos_framework> mesos_frameworks;
typedef std::vector<mesos_slave> mesos_slaves;

//
// component
//

inline const std::string& mesos_component::get_name() const
{
	return m_name;
}

inline void mesos_component::set_name(const std::string& name)
{
	m_name = name;
}

inline const std::string& mesos_component::get_uid() const{
	
	return m_uid;
}

inline void mesos_component::set_uid(const std::string& uid)
{
	m_uid = uid;
}

inline const mesos_pair_list& mesos_component::get_labels() const
{
	return m_labels;
}

inline void mesos_component::set_labels(mesos_pair_list&& labels)
{
	m_labels = std::move(labels);
}

inline void mesos_component::swap_labels(mesos_pair_list& new_labels)
{
	m_labels.swap(new_labels);
}

inline void mesos_component::push_label(const mesos_pair_t& label)
{
	m_labels.push_back(label);
}

inline void mesos_component::emplace_label(mesos_pair_t&& label)
{
	m_labels.emplace_back(label);
}

inline const std::string& mesos_component::get_name(const component_pair& p)
{
	return p.second;
}

inline mesos_component::type mesos_component::get_type(const component_pair& p)
{
	return p.first;
}

//
// framework
//

inline bool mesos_framework::has_task(const std::string& uid) const
{
	return m_tasks.find(uid) != m_tasks.end();
}

inline mesos_framework::task_ptr_t mesos_framework::get_task(const std::string& id)
{
	task_map::iterator it = m_tasks.find(id);
	if(it != m_tasks.end())
	{
		return it->second;
	}
	return 0;
}

inline bool mesos_framework::is_root_marathon(const std::string& name)
{
	return name == MARATHON_ROOT_NAME;
}

//
// task
//

