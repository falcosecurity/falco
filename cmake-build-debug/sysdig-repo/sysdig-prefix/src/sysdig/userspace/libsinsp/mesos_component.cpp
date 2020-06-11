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
// mesos_component.cpp
//
#ifndef CYGWING_AGENT

#include "mesos_component.h"
#include "marathon_component.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "json_error_log.h"
#include <sstream>
#include <iostream>

//
// component
//

const mesos_component::component_map mesos_component::list =
{
	{ mesos_component::MESOS_FRAMEWORK, "framework" },
	{ mesos_component::MESOS_TASK,      "task"      },
	{ mesos_component::MESOS_SLAVE,     "slave"     }
};

mesos_component::mesos_component(type t, const std::string& name, const std::string& uid) : 
	m_type(t),
	m_name(name), m_uid(uid)
{
	component_map::const_iterator it = list.find(t);
	if(it == list.end())
	{
		throw sinsp_exception("Invalid Mesos component type: " + std::to_string(t));
	}

	if(m_name.empty())
	{
		throw sinsp_exception("Mesos " + it->second + " name cannot be empty");
	}

	if(m_uid.empty())
	{
		throw sinsp_exception("Mesos " + it->second + " uid cannot be empty");
	}
}

mesos_component::mesos_component(const mesos_component& other): m_type(other.m_type),
	m_name(other.m_name),
	m_uid(other.m_uid),
	m_labels(other.m_labels)
{
}

mesos_component::mesos_component(mesos_component&& other):  m_type(other.m_type),
	m_name(std::move(other.m_name)),
	m_uid(std::move(other.m_uid)),
	m_labels(std::move(other.m_labels))
{
}

mesos_component& mesos_component::operator=(const mesos_component& other)
{
	m_type = other.m_type;
	m_name = other.m_name;
	m_uid = other.m_uid;
	m_labels = other.m_labels;
	return *this;
}

mesos_component& mesos_component::operator=(const mesos_component&& other)
{
	m_type = other.m_type;
	m_name = std::move(other.m_name);
	m_uid = std::move(other.m_uid);
	m_labels = other.m_labels;
	return *this;
}

std::string mesos_component::get_name(type t)
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

mesos_component::type mesos_component::get_type(const std::string& name)
{
	if(name == "framework")
	{
		return MESOS_FRAMEWORK;
	}
	else if(name == "task")
	{
		return MESOS_TASK;
	}
	else if(name == "slave")
	{
		return MESOS_SLAVE;
	}

	std::ostringstream os;
	os << "Unknown component name " << name;
	throw sinsp_exception(os.str().c_str());
}

mesos_pair_t* mesos_component::get_label(const mesos_pair_t& label)
{
	for (auto& lbl : m_labels)
	{
		if((lbl.first == label.first) && (lbl.second == label.second))
		{
			return &lbl;
		}
	}
	return 0;
}

void mesos_component::add_labels(mesos_pair_list&& labels)
{
	for (auto& label : labels)
	{
		if(!get_label(label))
		{
			emplace_label(std::move(label));
		}
	}
}


//
// framework
//

const std::string mesos_framework::MARATHON_ROOT_NAME = "marathon";

mesos_framework::mesos_framework(const std::string& name, const std::string& uid) :
	mesos_component(mesos_component::MESOS_FRAMEWORK, name, uid)
{
}

mesos_framework::~mesos_framework()
{
}

bool mesos_framework::is_framework_active(const Json::Value& framework)
{
	const Json::Value& active = framework["active"];
	if(!active.isNull() && active.isBool() && active.asBool())
	{
		return true;
	}
	return false;
}

void mesos_framework::add_or_replace_task(std::shared_ptr<mesos_task> task)
{
	m_tasks.insert({task->get_uid(), task});
}

void mesos_framework::remove_task(const std::string& uid)
{
	task_map::iterator it = m_tasks.find(uid);
	if(it != m_tasks.end())
	{
		m_tasks.erase(it);
		return;
	}
	g_logger.log("Removal of non-existing task (possible deployment failure): " + uid,
				sinsp_logger::SEV_WARNING);
}

const mesos_framework::task_map& mesos_framework::get_tasks() const
{
	return m_tasks;
}

mesos_framework::task_map& mesos_framework::get_tasks()
{
	return m_tasks;
}

//
// task
//

mesos_task::mesos_task(const std::string& name, const std::string& uid) :
	mesos_component(mesos_component::MESOS_TASK, name, uid)
{
}

mesos_task::~mesos_task()
{
}

mesos_task::mesos_task(const mesos_task& other): mesos_component(other),
	m_marathon_app_id(other.m_marathon_app_id),
	m_slave_id(other.m_slave_id)
{
}

mesos_task::mesos_task(mesos_task&& other): mesos_component(std::move(other)),
	m_marathon_app_id(std::move(other.m_marathon_app_id)),
	m_slave_id(std::move(other.m_slave_id))
{
}

mesos_task& mesos_task::operator=(const mesos_task& other)
{
	mesos_component::operator =(other);
	return *this;
}

mesos_task& mesos_task::operator=(const mesos_task&& other)
{
	mesos_component::operator =(std::move(other));
	return *this;
}

bool mesos_task::is_task_running(const Json::Value& task)
{
	const Json::Value& task_state = task["state"];
	if(!task_state.isNull() && task_state.isString())
	{
		return task_state.asString() == "TASK_RUNNING";
	}
	return false;
}

mesos_task::ptr_t mesos_task::make_task(const Json::Value& task)
{
	//g_logger.log(task.toStyledString(), sinsp_logger::SEV_DEBUG);
	std::string name, uid, sid;
	Json::Value fid = task["id"];
	if(!fid.isNull()) { uid = fid.asString(); }
	else
	{
		fid = task["taskId"];
		if(!fid.isNull()) { uid = fid.asString(); }
	}
	Json::Value fname = task["name"];
	if(!fname.isNull()) { name = fname.asString(); }
	else
	{
		std::string::size_type pos = uid.rfind('.');
		if(pos != std::string::npos)
		{
			name = uid.substr(0, pos);
		}
	}

	std::shared_ptr<mesos_task> t(new mesos_task(name, uid));

	Json::Value fsid = task["slave_id"];
	if(!fsid.isNull()) { sid = fsid.asString(); }
	else
	{
		Json::Value fsid = task["slaveId"];
		if(!fsid.isNull()) { sid = fsid.asString(); }
	}

	if(!sid.empty())
	{
		t->set_slave_id(sid);
	}
	add_labels(t, task);

	return t;
}

void mesos_task::add_labels(mesos_task::ptr_t task, const Json::Value& t_val)
{
	std::ostringstream os;
	if(task)
	{
		Json::Value labels = t_val["labels"];
		if(!labels.isNull())
		{
			for(const auto& label : labels)
			{
				std::string key, val;
				Json::Value lkey = label["key"];
				Json::Value lval = label["value"];
				if(!lkey.isNull())
				{
					key = lkey.asString();
				}
				if(!lval.isNull())
				{
					val = lval.asString();
				}
				os << "Adding Mesos task label: [" << key << ':' << val << ']';
				g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
				os.str("");
				task->emplace_label(mesos_pair_t(key, val));
			}
		}
	}
	else
	{
		os << "Attempt to add Mesos task labels to null task.";
		g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
		g_json_error_log.log("", os.str(), sinsp_utils::get_current_time_ns(), "mesos-task-add-labels");
	}
}

//
// slave
//

mesos_slave::mesos_slave(const std::string& name, const std::string& uid) :
	mesos_component(mesos_component::MESOS_SLAVE, name, uid)
{
}
#endif // CYGWING_AGENT

