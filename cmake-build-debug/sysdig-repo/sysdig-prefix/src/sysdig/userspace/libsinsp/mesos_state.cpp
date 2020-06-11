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
// k8s_state.cpp
//
#ifndef CYGWING_AGENT

#include "mesos_state.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <iostream>
#include <memory>

//
// state
//

mesos_state_t::mesos_state_t(bool is_captured, bool verbose) :
	m_verbose(verbose)
#ifdef HAS_CAPTURE
	, m_is_captured(is_captured)
#endif // HAS_CAPTURE
{
}

mesos_framework::task_ptr_t mesos_state_t::get_task(const std::string& uid) const
{
	for(auto& framework : get_frameworks())
	{
		for(auto& task : framework.get_tasks())
		{
			if(task.first == uid)
			{
				return task.second;
			}
		}
	}
	g_logger.log("Task not found: " + uid, sinsp_logger::SEV_WARNING);
	return 0;
}

std::unordered_set<std::string> mesos_state_t::get_all_task_ids() const
{
	std::unordered_set<std::string> tasks;
	for(const auto& framework : m_frameworks)
	{
		for(const auto& task : framework.get_tasks())
		{
			tasks.insert(task.first);
		}
	}
	return tasks;
}

const mesos_framework::task_map& mesos_state_t::get_tasks(const std::string& framework_uid) const
{
	for(const auto& framework : m_frameworks)
	{
		if(framework.get_uid() == framework_uid)
		{
			return framework.get_tasks();
		}
	}
	throw sinsp_exception("Framework not found: " + framework_uid);
}

mesos_framework::task_map& mesos_state_t::get_tasks(const std::string& framework_uid)
{
	for(auto& framework : m_frameworks)
	{
		if(framework.get_uid() == framework_uid)
		{
			return framework.get_tasks();
		}
	}
	throw sinsp_exception("Framework not found: " + framework_uid);
}

marathon_app::ptr_t mesos_state_t::get_app(const std::string& app_id)
{
	marathon_group::ptr_t group = get_app_group(app_id);
	if(group)
	{
		g_logger.log("Found group for app [" + app_id + "]: " + group->get_id(), sinsp_logger::SEV_DEBUG);
		return group->get_app(app_id);
	}
	return 0;
}

marathon_app::ptr_t mesos_state_t::get_app(mesos_task::ptr_t task) const
{
	for(const auto& group : m_groups)
	{
		marathon_app::ptr_t app = group.second->get_app(task);
		if(app)
		{
			return app;
		}
	}
	return 0;
}

marathon_group::ptr_t mesos_state_t::get_group(mesos_task::ptr_t task) const
{
	for(const auto& group : m_groups)
	{
		marathon_group::ptr_t grp = group.second->get_group(task);
		if(grp)
		{
			return grp;
		}
	}
	return 0;
}

marathon_group::app_ptr_t mesos_state_t::add_or_replace_app(const std::string& app_id,
															const std::string& group_id,
															const std::string& task_id)
{
	marathon_group::app_ptr_t app = get_app(app_id);
	if(!app)
	{
		app = std::make_shared<marathon_app>(app_id);
		g_logger.log("Created app [" + app_id + ']', sinsp_logger::SEV_DEBUG);
	}
	else
	{
		g_logger.log("Found app [" + app_id + ']', sinsp_logger::SEV_DEBUG);
	}
	if(!app)
	{
		std::string errstr = "Could not find or create app [" + app_id + ']';
		g_logger.log(errstr, sinsp_logger::SEV_ERROR);
		g_json_error_log.log(app_id, errstr, sinsp_utils::get_current_time_ns(), "add-replace-app");
		return 0;
	}

	if(!task_id.empty())
	{
		g_logger.log("Adding task [" + task_id + "] to app [" + app_id + ']', sinsp_logger::SEV_DEBUG);
		add_task_to_app(app, task_id);
	}

	marathon_group::ptr_t group = get_group(group_id);
	if(group)
	{
		g_logger.log("Adding app [" + app_id + "] to group [" + group_id + ']', sinsp_logger::SEV_DEBUG);
		group->add_or_replace_app(app);
	}

	return app;
}

void mesos_state_t::add_task_to_app(marathon_group::app_ptr_t app, const std::string& task_id)
{
	if(app)
	{
		mesos_framework::task_ptr_t pt = get_task(task_id);
		if(pt)
		{
			app->add_task(pt);
		}
		else
		{
			std::string errstr =  "Task [" + task_id + "] can not be obtained (null). Task not added to app [" + app->get_id() + ']';
			g_logger.log(errstr, sinsp_logger::SEV_ERROR);
			g_json_error_log.log(task_id, errstr, sinsp_utils::get_current_time_ns(), "add-task-to-app");
		}
	}
	else
	{
		std::string errstr = "Attempt to add task [" + task_id + "] to non-existing (null) app.";
		g_logger.log(errstr, sinsp_logger::SEV_ERROR);
		g_json_error_log.log(task_id, errstr, sinsp_utils::get_current_time_ns(), "add-task-to-app");
	}
}

marathon_group::ptr_t mesos_state_t::get_app_group(const std::string& app_id)
{
	std::string group_id = marathon_app::get_group_id(app_id);
	if(!group_id.empty())
	{
		return get_group(group_id);
	}
	return 0;
}

bool mesos_state_t::remove_app(const std::string& app_id)
{
	marathon_group::ptr_t group = get_group(app_id);
	if(group)
	{
		return group->remove_app(app_id);
	}
	return false;
}

marathon_group::ptr_t mesos_state_t::get_group(const std::string& group_id)
{
	marathon_groups::iterator it = m_groups.find(group_id);
	if(it != m_groups.end())
	{
		return it->second;
	}
	else
	{
		for(auto group : m_groups)
		{
			if(marathon_group::ptr_t p_group = group.second->get_group(group_id))
			{
				return p_group;
			}
		}
	}
	return 0;
}

marathon_group::ptr_t mesos_state_t::add_or_replace_group(marathon_group::ptr_t group, marathon_group::ptr_t to_group)
{
	std::string id = group->get_id();
	if(!to_group) // top level
	{
		marathon_groups::iterator it = m_groups.find(id);
		if(it != m_groups.end())
		{
			m_groups.erase(it);
		}
		m_groups.insert({id, group});
	}
	else
	{
		to_group->add_or_replace_group(group);
	}
	return group;
}

bool mesos_state_t::handle_groups(const Json::Value& root, marathon_group::ptr_t to_group, const std::string& framework_id)
{
	Json::Value groups = root["groups"];
	if(!groups.isNull() && groups.isArray())
	{
		for(const auto& group : groups)
		{
			add_group(group, to_group, framework_id);
		}
	}
	else
	{
		g_logger.log("No groups found.", sinsp_logger::SEV_WARNING);
		return false;
	}
	return true;
}

#ifdef HAS_CAPTURE
void mesos_state_t::capture_groups(const Json::Value& root, const std::string& framework_id, Json::Value& capt, bool capture_fw)
{
	if(!m_is_captured) { return; }

	capt["id"] = root["id"];
	const Json::Value& apps = root["apps"];
	if(!apps.isNull())
	{
		if(capture_fw)
		{
			capt["frameworkId"] = framework_id;
		}
		capt["apps"] = Json::arrayValue;
		for(const auto& app : apps)
		{
			Json::Value& c_app = capt["apps"].append(Json::Value());
			c_app["id"] = app["id"];

			// labels
			const Json::Value& labels = app["labels"];
			if(!labels.isNull())
			{
				c_app["labels"] = Json::objectValue;
				Json::Value::Members members = labels.getMemberNames();
				for (auto& member : members)
				{
					c_app["labels"][member] = labels[member];
				}
			}
		}
	}

	const Json::Value& groups = root["groups"];
	if(!groups.isNull())
	{
		capt["groups"] = Json::arrayValue;
		for(const auto& group : groups)
		{
			Json::Value& c_group = capt["groups"].append(Json::objectValue);
			capture_groups(group, framework_id, c_group);
		}
	}
}

void mesos_state_t::capture_apps(const Json::Value& root, const std::string& framework_id)
{
	if(!m_is_captured) { return; }

	Json::Value capt;
	const Json::Value& apps = root["apps"];
	if(!apps.isNull())
	{
		capt["frameworkId"] = framework_id;
		capt["apps"] = Json::arrayValue;
		for(const auto& app : apps)
		{
			Json::Value& c_app = capt["apps"].append(Json::Value());
			c_app["id"] = app["id"];

			// labels
			const Json::Value& labels = app["labels"];
			if(!labels.isNull())
			{
				c_app["labels"] = Json::objectValue;
				Json::Value::Members members = labels.getMemberNames();
				for (auto& member : members)
				{
					c_app["labels"][member] = labels[member];
				}
			}

			// tasks
			const Json::Value& tasks = app["tasks"];
			if(!tasks.isNull())
			{
				c_app["tasks"] = Json::arrayValue;
				for(const auto& task : tasks)
				{
					Json::Value& c_task = c_app["tasks"].append(Json::objectValue);
					c_task["id"] = task["id"];
					c_task["host"] = task["host"];
					c_task["slaveId"] = task["slaveId"];
					c_task["appId"] = task["appId"];
				}
			}
		}
	}
	enqueue_capture_event(capture::MARATHON_APPS, Json::FastWriter().write(capt));
}
#endif // HAS_CAPTURE

bool mesos_state_t::parse_groups(Json::Value&& root, const std::string& framework_id)
{
	add_group(root, 0, framework_id);
#ifdef HAS_CAPTURE
	if(m_is_captured)
	{
		Json::Value capt;
		capture_groups(root, framework_id, capt, true);
		enqueue_capture_event(capture::MARATHON_GROUPS, Json::FastWriter().write(capt));
	}
#endif // HAS_CAPTURE
	if(m_verbose)
	{
		std::cout << Json::FastWriter().write(root) << std::endl;
	}
	return true;
}

bool mesos_state_t::parse_groups(json_ptr_t json, const std::string& framework_id)
{
	if(json && !json->isNull() && !(*json)["id"].isNull())
	{
		return parse_groups(std::move(*json), framework_id);
	}
	else
	{
		throw sinsp_exception("Marathon groups parsing failed (Invalid JSON).");
	}
}

void mesos_state_t::erase_groups(const std::string& framework_id)
{
	for(marathon_groups::iterator it = m_groups.begin(); it != m_groups.end();)
	{
		if(it->second->get_framework_id() == framework_id)
		{
			m_groups.erase(it++);
		}
		else { ++it; }
	}
}

void mesos_state_t::print_groups() const
{
	for(auto& group : m_groups)
	{
		group.second->print();
	}
}

marathon_group::ptr_t mesos_state_t::add_group(const Json::Value& group, marathon_group::ptr_t to_group, const std::string& framework_id)
{
	const Json::Value& group_id = group["id"];
	if(!group_id.isNull())
	{
		std::string id = group_id.asString();
		std::ostringstream os;
		os << "Adding Marathon group [" << id << ']';
		if(to_group)
		{
			os << " to group [" << to_group->get_id() << ']';
		}
		g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);

		marathon_group::ptr_t pg(new marathon_group(id, framework_id));
		add_or_replace_group(pg, to_group);

		const Json::Value& apps = group["apps"];
		if(!apps.isNull())
		{
			for(const auto& app : apps)
			{
				const Json::Value& app_id = app["id"];
				if(!app_id.isNull())
				{
					const Json::Value& instances = app["instances"];
					if(!instances.isNull() && instances.isInt() && instances.asInt() > 0)
					{
						marathon_app::ptr_t p_app = get_app(app_id.asString());
						if(!p_app)
						{
							p_app = add_app(app, framework_id);
						}
						if(p_app)
						{
							pg->add_or_replace_app(p_app);
							if(!framework_id.empty())
							{
								for(const auto& task : get_tasks(framework_id))
								{
									if(task.second->get_marathon_app_id() == app_id.asString())
									{
										add_task_to_app(p_app, task.first);
									}
								}
							}
						}
						else
						{
							std::string errstr = "An error occurred adding app [" + app_id.asString() +
								"] to group [" + id + ']';
							g_logger.log(errstr, sinsp_logger::SEV_ERROR);
							g_json_error_log.log(app_id.asString(), errstr, sinsp_utils::get_current_time_ns(), "add-group");
						}
					}
				}
			}
		}

		Json::Value groups = group["groups"];
		if(!groups.isNull() && groups.isArray())
		{
			handle_groups(group, pg, framework_id);
		}
		return pg;
	}
	return 0;
}

void mesos_state_t::parse_apps(Json::Value&& root, const std::string& framework_id)
{
	const Json::Value& apps = root["apps"];
	if(!apps.isNull())
	{
		for(const auto& app : apps)
		{
			add_app(app, framework_id);
		}
#ifdef HAS_CAPTURE
		if(m_is_captured)
		{
			capture_apps(root, framework_id);
		}
#endif // HAS_CAPTURE
		if(m_verbose)
		{
			std::cout << Json::FastWriter().write(root) << std::endl;
		}
	}
	else
	{
		g_logger.log("No apps found.", sinsp_logger::SEV_WARNING);
	}
}

void mesos_state_t::parse_apps(json_ptr_t json, const std::string& framework_id)
{
	if(json && !json->isNull())
	{
		parse_apps(std::move(*json), framework_id);
	}
	else
	{
		throw sinsp_exception("Invalid JSON (Marathon apps parsing failed).");
	}
}

marathon_app::ptr_t mesos_state_t::add_app(const Json::Value& app, const std::string& /*framework_id*/)
{
	marathon_app::ptr_t p_app = 0;
	const Json::Value& app_id = app["id"];
	if(!app_id.isNull())
	{
		std::string id = app_id.asString();
		g_logger.log("Adding Marathon app: " + id, sinsp_logger::SEV_DEBUG);
		std::string group_id = marathon_app::get_group_id(id);
		if(!group_id.empty())
		{
			p_app = add_or_replace_app(id, group_id);
			if(p_app)
			{
				const Json::Value& labels = app["labels"];
				if(!labels.isNull())
				{
					p_app->set_labels(labels);
				}
				g_logger.log("Added app [" + id + "] to Marathon group: [" + group_id + ']', sinsp_logger::SEV_DEBUG);
				const Json::Value& tasks = app["tasks"];
				if(tasks.size())
				{
					g_logger.log("App [" + id + "] has " + std::to_string(tasks.size()) + " tasks.", sinsp_logger::SEV_DEBUG);
					for(const auto& task : tasks)
					{
						Json::Value task_id = task["id"];
						if(!task_id.isNull())
						{
							std::string tid = task_id.asString();
							g_logger.log("Adding Mesos task ID to app [" + id + "]: " + tid, sinsp_logger::SEV_DEBUG);
							mesos_framework::task_ptr_t pt = get_task(task_id.asString());
							if(pt)
							{
								pt->set_marathon_app_id(id);
								add_task_to_app(p_app, tid);
							}
							else
							{
								std::string errstr = "Marathon task not found in mesos state: " + tid;
								g_logger.log(errstr, sinsp_logger::SEV_WARNING);
								g_json_error_log.log(tid, errstr, sinsp_utils::get_current_time_ns(), "add-app");
							}
						}
					}
				}
			}
			else
			{
				std::string errstr = "NOT added app [" + id + "] to Marathon group: [" + group_id + ']';
				g_logger.log(errstr, sinsp_logger::SEV_ERROR);
				g_json_error_log.log(id, errstr, sinsp_utils::get_current_time_ns(), "add-app");
			}
		}
		else
		{
			std::string errstr = "Could not determine group ID for app: " + id;
			g_logger.log(errstr, sinsp_logger::SEV_ERROR);
			g_json_error_log.log(id, errstr, sinsp_utils::get_current_time_ns(), "add-app");
		}
	}
	return p_app;
}
#endif // CYGWING_AGENT

