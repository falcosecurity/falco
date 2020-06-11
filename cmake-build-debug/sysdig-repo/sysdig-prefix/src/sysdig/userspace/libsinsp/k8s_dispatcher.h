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
// k8s_dispatcher.h
//
// kubernetes REST API notification abstraction
//

#pragma once

#include "k8s.h"
#include "k8s_component.h"
#include "k8s_state.h"
#include "k8s_event_data.h"
#include "json/json.h"
#include <deque>
#include <string>

class k8s_dispatcher
{
public:
	typedef user_event_filter_t::ptr_t filter_ptr_t;

	enum msg_reason
	{
		COMPONENT_ADDED,
		COMPONENT_MODIFIED,
		COMPONENT_DELETED,
		COMPONENT_ERROR,
		COMPONENT_UNKNOWN // only to mark bad event messages
	};

	struct msg_data
	{
		msg_reason  m_reason = COMPONENT_UNKNOWN;
		std::string m_name;
		std::string m_uid;
		std::string m_namespace;

		bool is_valid() const
		{
			return m_reason != COMPONENT_UNKNOWN;
		}
	};

	k8s_dispatcher() = delete;

	k8s_dispatcher(k8s_component::type t,
		k8s_state_t& state,
		filter_ptr_t event_filter = nullptr);

	void enqueue(k8s_event_data&& data);

	void extract_data(const std::string& json, bool enqueue = false);
	void extract_data(Json::Value& root, bool enqueue = false);

	// clears the content of labels and fills it with new values, if any
	template <typename T>
	static void handle_labels(T& component, const Json::Value& metadata, const std::string& name)
	{
		if(!metadata.isNull())
		{
			k8s_pair_list entries = k8s_component::extract_object(metadata, name);
			component.set_labels(std::move(entries));
		}
		else
		{
			g_logger.log("Null metadata object received", sinsp_logger::SEV_ERROR);
		}
	}

	// clears the content of selectors and fills it with new values, if any;
	// the selector location depth in JSON tree is detected and handled accordingly
	template <typename T>
	static void handle_selectors(T& component, const Json::Value& spec)
	{
		if(!spec.isNull())
		{
			const Json::Value& selector = spec["selector"];
			if(!selector.isNull())
			{
				const Json::Value& match_labels = selector["matchLabels"];
				k8s_pair_list selectors = match_labels.isNull() ?
										  k8s_component::extract_object(spec, "selector") :
										  k8s_component::extract_object(selector, "matchLabels");
				component.set_selectors(std::move(selectors));
			}
			else
			{
				g_logger.log("K8s: Null selector object.", sinsp_logger::SEV_ERROR);
			}
		}
		else
		{
			g_logger.log("K8s: Null spec object.", sinsp_logger::SEV_ERROR);
		}
	}

private:
	const std::string& next_msg();
	
	msg_data get_msg_data(Json::Value& root);

	bool is_valid(const std::string& msg);

	bool is_ready(const std::string& msg);

	void remove();

	void dispatch();

	void handle_node(const Json::Value& root, const msg_data& data);
	void handle_namespace(const Json::Value& root, const msg_data& data);
	bool handle_pod(const Json::Value& root, const msg_data& data);
	void handle_service(const Json::Value& root, const msg_data& data);
	void handle_deployment(const Json::Value& root, const msg_data& data);
	void handle_daemonset(const Json::Value& root, const msg_data& data);
	void handle_event(const Json::Value& root, const msg_data& data);

	// handler for replication controllers and replica sets
	template<typename T>
	void handle_rc(const Json::Value& root, const msg_data& data, T& cont, const std::string& comp_name)
	{
		typedef typename T::value_type comp_t;

		if(data.m_reason == COMPONENT_ADDED)
		{
			if(m_state.has(cont, data.m_uid))
			{
				std::ostringstream os;
				os << "ADDED message received for existing " << comp_name << '[' << data.m_uid << "], updating only.";
				g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
			}
			comp_t& rc = m_state.get_component<T, comp_t>(cont, data.m_name, data.m_uid, data.m_namespace);
			const Json::Value& object = root["object"];
			if(!object.isNull())
			{
				handle_labels(rc, object["metadata"], "labels");
				const Json::Value& spec = object["spec"];
				handle_selectors(rc, spec);
				rc.set_replicas(object);
			}
			else
			{
				g_logger.log("K8s: object is null for " + comp_name + ' ' + data.m_name + '[' + data.m_uid + ']',
							 sinsp_logger::SEV_ERROR);
			}
		}
		else if(data.m_reason == COMPONENT_MODIFIED)
		{
			if(!m_state.has(cont, data.m_uid))
			{
				std::ostringstream os;
				os << "MODIFIED message received for non-existing " << comp_name << '[' << data.m_uid << "], giving up.";
				g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
				return;
			}
			comp_t& rc = m_state.get_component<T, comp_t>(cont, data.m_name, data.m_uid, data.m_namespace);
			const Json::Value& object = root["object"];
			if(!object.isNull())
			{
				handle_labels(rc, object["metadata"], "labels");
				handle_selectors(rc, object["spec"]);
				rc.set_replicas(object);
			}
			else
			{
				g_logger.log("K8s: object is null for " + comp_name + ' ' + data.m_name + '[' + data.m_uid + ']',
							 sinsp_logger::SEV_ERROR);
			}
		}
		else if(data.m_reason == COMPONENT_DELETED)
		{
			if(!m_state.delete_component(cont, data.m_uid))
			{
				g_logger.log("K8s: " + comp_name + " not found: " + data.m_name, sinsp_logger::SEV_ERROR);
			}
		}
		else if(data.m_reason == COMPONENT_ERROR)
		{
			log_error(root, comp_name);
		}
		else
		{
			g_logger.log(std::string("Unsupported K8S " + comp_name + " event reason: ") + std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
		}
	}

	void log_error(const Json::Value& root, const std::string& comp);

	static std::string to_reason_desc(msg_reason reason);

	static msg_reason to_reason(const std::string& desc);

	typedef std::deque<std::string> list;

	k8s_component::type m_type;
	list                m_messages;
	k8s_state_t&        m_state;
	filter_ptr_t        m_event_filter;
	std::string         m_machine_id;
};


inline const std::string& k8s_dispatcher::next_msg()
{
	return m_messages.front();
}

inline void k8s_dispatcher::remove()
{
	m_messages.pop_front();
}