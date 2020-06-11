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
// k8s_dispatcher.cpp
//
#ifndef CYGWING_AGENT

#include "k8s_dispatcher.h"
#include "k8s_service_handler.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <assert.h>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iostream>


k8s_dispatcher::k8s_dispatcher(k8s_component::type t, k8s_state_t& state,
							   filter_ptr_t event_filter):
	m_type(t), m_state(state), m_event_filter(event_filter)
{
}

void k8s_dispatcher::enqueue(k8s_event_data&& event_data)
{
	assert(event_data.component() == m_type);

	std::string data = event_data.data();

	if(m_messages.size() == 0)
	{
		m_messages.push_back("");
	}

	std::string* msg = &m_messages.back();
	std::string::size_type pos = msg->find_first_of('\n');

	// previous msg full, this is a beginning of new message
	if(pos != std::string::npos && pos == (msg->size() - 1))
	{
		m_messages.push_back("");
		msg = &m_messages.back();
	}

	while ((pos = data.find_first_of('\n')) != std::string::npos)
	{
		msg->append(data.substr(0, pos + 1));
		if(data.length() > pos + 1)
		{
			data = data.substr(pos + 1);
			m_messages.push_back("");
			msg = &m_messages.back();
		}
		else
		{
			break;
		}
	};

	if(data.size() > 0)
	{
		msg->append(data);
	}

	dispatch(); // candidate for separate thread
}

bool k8s_dispatcher::is_valid(const std::string& msg)
{
	// zero-length message is valid because that's how it starts its life.
	// so, here we only check for messages that are single newline only
	// or those that are longer than one character and contain multiple newlines.

	if((msg.size() == 1 && msg[0] == '\n') ||
		std::count(msg.begin(), msg.end(), '\n') > 1)
	{
		return false;
	}
	return true;
}

bool k8s_dispatcher::is_ready(const std::string& msg)
{
	// absurd minimum ( "{}\n" ) but it's hard to tell 
	// what minimal size is, so there ...
	if(msg.size() < 3) 
	{
		return false;
	}
	return msg[msg.size() - 1] == '\n';
}

k8s_dispatcher::msg_data k8s_dispatcher::get_msg_data(Json::Value& root)
{
	msg_data data;
	Json::Value evtype = root["type"];
	if(!evtype.isNull() && evtype.isString())
	{
		const std::string& et = evtype.asString();
		if(!et.empty())
		{
			if(et[0] == 'A') { data.m_reason = COMPONENT_ADDED; }
			else if(et[0] == 'M') { data.m_reason = COMPONENT_MODIFIED; }
			else if(et[0] == 'D') { data.m_reason = COMPONENT_DELETED; }
			else if(et[0] == 'E') { data.m_reason = COMPONENT_ERROR; }
		}
		else
		{
			return msg_data();
		}
	}
	Json::Value object = root["object"];

	// +++ for capture
	Json::Value kind = object["kind"];
	if(!kind.isNull() && kind.isString() && root["kind"].isNull())
	{
		root["kind"] = kind.asString();
	}
	Json::Value api_version = object["apiVersion"];
	if(!api_version.isNull() && api_version.isString() && root["apiVersion"].isNull())
	{
		root["apiVersion"] = api_version.asString();
	}
	// --- for capture

	if(!object.isNull() && object.isObject())
	{
		Json::Value meta = object["metadata"];
		if(!meta.isNull() && meta.isObject())
		{
			Json::Value name = meta["name"];
			if(!name.isNull())
			{
				data.m_name = name.asString();
			}
			Json::Value uid = meta["uid"];
			if(!uid.isNull())
			{
				data.m_uid = uid.asString();
			}
			Json::Value nspace = meta["namespace"];
			if(!nspace.isNull())
			{
				data.m_namespace = nspace.asString();
			}
		}
	}
	return data;
}

void k8s_dispatcher::log_error(const Json::Value& root, const std::string& comp)
{
	std::string unk_err = "Unknown.";
	std::ostringstream os;
	os << "K8S server reported " << comp << " error: ";
	if(!root.isNull())
	{
		Json::Value object = root["object"];
		if(!object.isNull())
		{
			os << object.toStyledString();
			unk_err.clear();
		}
	}
	os << unk_err;
	g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
}

void k8s_dispatcher::handle_node(const Json::Value& root, const msg_data& data)
{
	if(data.m_reason == COMPONENT_ADDED)
	{
		if(m_state.has(m_state.get_nodes(), data.m_uid))
		{
			std::ostringstream os;
			os << "ADDED message received for existing node [" << data.m_uid << "], updating only.";
			g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
		}
		k8s_node_t& node = m_state.get_component<k8s_nodes, k8s_node_t>(m_state.get_nodes(), data.m_name, data.m_uid);
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			const Json::Value& status = object["status"];
			if(!status.isNull())
			{
				k8s_node_t::host_ip_list addresses = k8s_node_t::extract_addresses(status);
				if(addresses.size() > 0)
				{
					node.set_host_ips(std::move(addresses));
				}
			}
			Json::Value metadata = object["metadata"];
			if(!metadata.isNull())
			{
				k8s_pair_list entries = k8s_component::extract_object(metadata, "labels");
				if(entries.size() > 0)
				{
					node.set_labels(std::move(entries));
				}
			}
		}
	}
	else if(data.m_reason == COMPONENT_MODIFIED)
	{
		if(!m_state.has(m_state.get_nodes(), data.m_uid))
		{
			std::ostringstream os;
			os << "MODIFIED message received for non-existing node [" << data.m_uid << "], giving up.";
			g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
			return;
		}
		k8s_node_t& node = m_state.get_component<k8s_nodes, k8s_node_t>(m_state.get_nodes(), data.m_name, data.m_uid);
		Json::Value object = root["object"];
		if(!object.isNull())
		{
			const Json::Value& status = object["status"];
			if(!status.isNull())
			{
				k8s_node_t::host_ip_list addresses = k8s_node_t::extract_addresses(status);
				if(addresses.size() > 0)
				{
					node.set_host_ips(std::move(addresses));
				}
			}
			const Json::Value& metadata = object["metadata"];
			if(!metadata.isNull())
			{
				k8s_pair_list entries = k8s_component::extract_object(metadata, "labels");
				if(entries.size() > 0)
				{
					node.add_labels(std::move(entries));
				}
			}
		}
	}
	else if(data.m_reason == COMPONENT_DELETED)
	{
		if(!m_state.delete_component(m_state.get_nodes(), data.m_uid))
		{
			g_logger.log(std::string("NODE not found: ") + data.m_name, sinsp_logger::SEV_ERROR);
		}
	}
	else if(data.m_reason == COMPONENT_ERROR)
	{
		log_error(root, "NODE");
	}
	else
	{
		g_logger.log(std::string("Unsupported K8S NODE event reason: ") + std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
	}
}

void k8s_dispatcher::handle_namespace(const Json::Value& root, const msg_data& data)
{
	if(data.m_reason == COMPONENT_ADDED)
	{
		if(m_state.has(m_state.get_namespaces(), data.m_uid))
		{
			std::ostringstream os;
			os << "ADDED message received for existing namespace [" << data.m_uid << "], updating only.";
			g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
		}
		k8s_ns_t& ns = m_state.get_component<k8s_namespaces, k8s_ns_t>(m_state.get_namespaces(), data.m_name, data.m_uid);
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			const Json::Value& metadata = object["metadata"];
			if(!metadata.isNull())
			{
				k8s_pair_list entries = k8s_component::extract_object(metadata, "labels");
				if(entries.size() > 0)
				{
					ns.set_labels(std::move(entries));
				}
			}
		}
	}
	else if(data.m_reason == COMPONENT_MODIFIED)
	{
		if(!m_state.has(m_state.get_namespaces(), data.m_uid))
		{
			std::ostringstream os;
			os << "MODIFIED message received for non-existing namespace [" << data.m_uid << "], giving up.";
			g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
			return;
		}
		k8s_ns_t& ns = m_state.get_component<k8s_namespaces, k8s_ns_t>(m_state.get_namespaces(), data.m_name, data.m_uid);
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			const Json::Value& metadata = object["metadata"];
			if(!metadata.isNull())
			{
				k8s_pair_list entries = k8s_component::extract_object(metadata, "labels");
				if(entries.size() > 0)
				{
					ns.add_labels(std::move(entries));
				}
			}
		}
	}
	else if(data.m_reason == COMPONENT_DELETED)
	{
		if(!m_state.delete_component(m_state.get_namespaces(), data.m_uid))
		{
			g_logger.log(std::string("NAMESPACE not found: ") + data.m_name, sinsp_logger::SEV_ERROR);
		}
	}
	else if(data.m_reason == COMPONENT_ERROR)
	{
		log_error(root, "NAMESPACE");
	}
	else
	{
		g_logger.log(std::string("Unsupported K8S NAMESPACE event reason: ") + std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
	}
}

bool k8s_dispatcher::handle_pod(const Json::Value& root, const msg_data& data)
{
	if(data.m_reason == COMPONENT_ADDED)
	{
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			if(m_state.has(m_state.get_pods(), data.m_uid))
			{
				std::ostringstream os;
				os << "ADDED message received for existing pod [" << data.m_uid << "], updating only.";
				g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
			}
			k8s_pod_t& pod = m_state.get_component<k8s_pods, k8s_pod_t>(m_state.get_pods(), data.m_name, data.m_uid, data.m_namespace);
			handle_labels(pod, object["metadata"], "labels");
			m_state.update_pod(pod, object);
		}
	}
	else if(data.m_reason == COMPONENT_MODIFIED)
	{
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			if(!m_state.has(m_state.get_pods(), data.m_uid))
			{
				std::ostringstream os;
				os << "MODIFIED message received for non-existing pod [" << data.m_uid << "], giving up.";
				g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
				return false;
			}
			k8s_pod_t& pod = m_state.get_component<k8s_pods, k8s_pod_t>(m_state.get_pods(), data.m_name, data.m_uid, data.m_namespace);
			handle_labels(pod, object["metadata"], "labels");
			m_state.update_pod(pod, object);
		}
	}
	else if(data.m_reason == COMPONENT_DELETED)
	{
		k8s_pod_t* pod = m_state.get_component<k8s_pods, k8s_pod_t>(m_state.get_pods(), data.m_uid);
		if(pod)
		{
			if(!m_state.delete_component(m_state.get_pods(), data.m_uid))
			{
				g_logger.log(std::string("Error deleting POD: ") + data.m_name, sinsp_logger::SEV_ERROR);
				return false;
			}
		}
		else
		{
			g_logger.log(std::string("POD not found: ") + data.m_name, sinsp_logger::SEV_WARNING);
			return false;
		}
	}
	else if(data.m_reason == COMPONENT_ERROR)
	{
		log_error(root, "POD");
	}
	else
	{
		g_logger.log(std::string("Unsupported K8S POD event reason: ") + std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
		return false;
	}
	return true;
}

void k8s_dispatcher::handle_service(const Json::Value& root, const msg_data& data)
{
	if(data.m_reason == COMPONENT_ADDED)
	{
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			if(m_state.has(m_state.get_services(), data.m_uid))
			{
				std::ostringstream os;
				os << "ADDED message received for existing service [" << data.m_uid << "], updating only.";
				g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
			}
			k8s_service_t& service = m_state.get_component<k8s_services, k8s_service_t>(m_state.get_services(), data.m_name, data.m_uid, data.m_namespace);
			handle_labels(service, object["metadata"], "labels");
			handle_selectors(service, object["spec"]);
			k8s_service_handler::extract_services_data(object, service, m_state.get_pods());
		}
		else
		{
			g_logger.log("K8s: object is null for service " + data.m_name + '[' + data.m_uid + ']', sinsp_logger::SEV_ERROR);
		}
	}
	else if(data.m_reason == COMPONENT_MODIFIED)
	{
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			if(!m_state.has(m_state.get_services(), data.m_uid))
			{
				std::ostringstream os;
				os << "MODIFIED message received for non-existing service [" << data.m_uid << "], giving up.";
				g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
				return;
			}
			k8s_service_t& service = m_state.get_component<k8s_services, k8s_service_t>(m_state.get_services(), data.m_name, data.m_uid, data.m_namespace);
			handle_labels(service, object["metadata"], "labels");
			handle_selectors(service, object["spec"]);
			k8s_service_handler::extract_services_data(object, service, m_state.get_pods());
		}
		else
		{
			g_logger.log("K8s: object is null for service " + data.m_name + '[' + data.m_uid + ']', sinsp_logger::SEV_ERROR);
		}
	}
	else if(data.m_reason == COMPONENT_DELETED)
	{
		if(!m_state.delete_component(m_state.get_services(), data.m_uid))
		{
			g_logger.log(std::string("SERVICE not found: ") + data.m_name, sinsp_logger::SEV_ERROR);
		}
	}
	else if(data.m_reason == COMPONENT_ERROR)
	{
		log_error(root, "SERVICE");
	}
	else
	{
		g_logger.log(std::string("Unsupported K8S SERVICE event reason: ") + std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
	}
}

void k8s_dispatcher::handle_deployment(const Json::Value& root, const msg_data& data)
{
	if(data.m_reason == COMPONENT_ADDED)
	{
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			if(m_state.has(m_state.get_deployments(), data.m_uid))
			{
				std::ostringstream os;
				os << "ADDED message received for existing deployment [" << data.m_uid << "], updating only.";
				g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
			}
			k8s_deployment_t& deployment = m_state.get_component<k8s_deployments, k8s_deployment_t>(m_state.get_deployments(), data.m_name, data.m_uid, data.m_namespace);
			handle_labels(deployment, object["metadata"], "labels");
			handle_selectors(deployment, object["spec"]);
			deployment.set_replicas(object);
		}
		else
		{
			g_logger.log("K8s: object is null for deployment "+ data.m_name + '[' + data.m_uid + ']', sinsp_logger::SEV_ERROR);
		}
	}
	else if(data.m_reason == COMPONENT_MODIFIED)
	{
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			if(!m_state.has(m_state.get_deployments(), data.m_uid))
			{
				std::ostringstream os;
				os << "MODIFIED message received for non-existing deployment [" << data.m_uid << "], giving up.";
				g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
				return;
			}
			k8s_deployment_t& deployment =
			m_state.get_component<k8s_deployments, k8s_deployment_t>(m_state.get_deployments(), data.m_name, data.m_uid, data.m_namespace);
			handle_labels(deployment, object["metadata"], "labels");
			handle_selectors(deployment, object["spec"]);
			deployment.set_replicas(object);
		}
		else
		{
			g_logger.log("K8s: object is null for deployment " + data.m_name + '[' + data.m_uid + ']', sinsp_logger::SEV_ERROR);
		}
	}
	else if(data.m_reason == COMPONENT_DELETED)
	{
		if(!m_state.delete_component(m_state.get_deployments(), data.m_uid))
		{
			g_logger.log(std::string("DEPLOYMENT not found: ") + data.m_name, sinsp_logger::SEV_ERROR);
		}
	}
	else if(data.m_reason == COMPONENT_ERROR)
	{
		log_error(root, "DEPLOYMENT");
	}
	else
	{
		g_logger.log(std::string("Unsupported K8S DEPLOYMENT event reason: ") + std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
	}
}

void k8s_dispatcher::handle_daemonset(const Json::Value& root, const msg_data& data)
{
	if(data.m_reason == COMPONENT_ADDED)
	{
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			if(m_state.has(m_state.get_daemonsets(), data.m_uid))
			{
				std::ostringstream os;
				os << "ADDED message received for existing daemonset [" << data.m_uid << "], updating only.";
				g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
			}
			k8s_daemonset_t& daemonset = m_state.get_component<k8s_daemonsets, k8s_daemonset_t>(m_state.get_daemonsets(), data.m_name, data.m_uid, data.m_namespace);
			handle_labels(daemonset, object["metadata"], "labels");
			handle_selectors(daemonset, object["spec"]);
			daemonset.set_scheduled(object);
		}
	}
	else if(data.m_reason == COMPONENT_MODIFIED)
	{
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			if(!m_state.has(m_state.get_daemonsets(), data.m_uid))
			{
				std::ostringstream os;
				os << "MODIFIED message received for non-existing daemonset [" << data.m_uid << "], giving up.";
				g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
				return;
			}
			k8s_daemonset_t& daemonset = m_state.get_component<k8s_daemonsets, k8s_daemonset_t>(m_state.get_daemonsets(), data.m_name, data.m_uid, data.m_namespace);
			handle_labels(daemonset, object["metadata"], "labels");
			handle_selectors(daemonset, object["spec"]);
			daemonset.set_scheduled(object);
		}
	}
	else if(data.m_reason == COMPONENT_DELETED)
	{
		if(!m_state.delete_component(m_state.get_daemonsets(), data.m_uid))
		{
			g_logger.log(std::string("DAEMONSET not found: ") + data.m_name, sinsp_logger::SEV_ERROR);
		}
	}
	else if(data.m_reason == COMPONENT_ERROR)
	{
		log_error(root, "DAEMONSET");
	}
	else
	{
		g_logger.log(std::string("Unsupported K8S DAEMONSET event reason: ") + std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
	}
}

void k8s_dispatcher::handle_event(const Json::Value& root, const msg_data& data)
{
	if(m_event_filter)
	{
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			g_logger.log("K8s EVENT: object found.", sinsp_logger::SEV_TRACE);
			const Json::Value& involved_object = object["involvedObject"];
			if(!involved_object.isNull())
			{
				bool is_aggregate = (get_json_string(object , "message").find("events with common reason combined") != std::string::npos);
				time_t last_ts = get_epoch_utc_seconds(get_json_string(object , "lastTimestamp"));
				time_t now_ts = get_epoch_utc_seconds_now();
				g_logger.log("K8s EVENT: lastTimestamp=" + std::to_string(last_ts) + ", now_ts=" + std::to_string(now_ts), sinsp_logger::SEV_TRACE);
				if(((last_ts > 0) && (now_ts > 0)) && // we got good timestamps
					!is_aggregate && // not an aggregated cached event
					((now_ts - last_ts) < 10)) // event not older than 10 seconds
				{
					const Json::Value& kind = involved_object["kind"];
					const Json::Value& event_reason = object["reason"];
					g_logger.log("K8s EVENT: involved object and event reason found:" + kind.asString() + '/' + event_reason.asString(), sinsp_logger::SEV_TRACE);
					if(!kind.isNull() && kind.isConvertibleTo(Json::stringValue) &&
						!event_reason.isNull() && event_reason.isConvertibleTo(Json::stringValue))
					{
						bool is_allowed = m_event_filter->allows_all();
						std::string type = kind.asString();
						if(!is_allowed && !type.empty())
						{
							std::string reason = event_reason.asString();
							is_allowed = m_event_filter->allows_all(type);
							if(!is_allowed && !reason.empty())
							{
								is_allowed = m_event_filter->has(type, reason);
							}
						}
						if(is_allowed)
						{
							g_logger.log("K8s EVENT: adding event.", sinsp_logger::SEV_TRACE);
							k8s_event_t& evt = m_state.add_component<k8s_events, k8s_event_t>(m_state.get_events(),
														data.m_name, data.m_uid, data.m_namespace);
							m_state.update_event(evt, object);
						}
						else
						{
							g_logger.log("K8s EVENT: filter does not allow {\"" + type + "\", \"{" + event_reason.asString() + "\"} }", sinsp_logger::SEV_TRACE);
							g_logger.log(m_event_filter->to_string(), sinsp_logger::SEV_TRACE);
						}
					}
					else
					{
						g_logger.log("K8s EVENT: event type or involvedObject kind not found.", sinsp_logger::SEV_ERROR);
						g_logger.log(Json::FastWriter().write(root), sinsp_logger::SEV_TRACE);
					}
				}
				else
				{
					g_logger.log("K8s EVENT: old event, ignoring: "
								 ", lastTimestamp=" + std::to_string(last_ts) + ", now_ts=" + std::to_string(now_ts),
								sinsp_logger::SEV_DEBUG);
				}
			}
			else
			{
				g_logger.log("K8s EVENT: involvedObject not found.", sinsp_logger::SEV_ERROR);
				g_logger.log(Json::FastWriter().write(root), sinsp_logger::SEV_TRACE);
			}
		}
		else
		{
			g_logger.log("K8s EVENT: object not found.", sinsp_logger::SEV_ERROR);
			g_logger.log(Json::FastWriter().write(root), sinsp_logger::SEV_TRACE);
		}
	}
	else
	{
		g_logger.log("K8s EVENT: filter NOT found.", sinsp_logger::SEV_DEBUG);
	}
}

void k8s_dispatcher::extract_data(Json::Value& root, bool enqueue)
{
	std::ostringstream os;
	msg_data data = get_msg_data(root);
	if(data.is_valid())
	{
		std::ostringstream os;
		os << '[' << to_reason_desc(data.m_reason) << ',';
		switch (m_type)
		{
			case k8s_component::K8S_NODES:
				os << "NODE,";
				handle_node(root, data);
				break;
			case k8s_component::K8S_NAMESPACES:
				os << "NAMESPACE,";
				handle_namespace(root, data);
				break;
			case k8s_component::K8S_PODS:
				os << "POD,";
				if(handle_pod(root, data)) { break; }
				else { return; }
			case k8s_component::K8S_REPLICATIONCONTROLLERS:
				os << "REPLICATION_CONTROLLER,";
				handle_rc(root, data, m_state.get_rcs(), "replication controller");
				break;
			case k8s_component::K8S_REPLICASETS:
				os << "REPLICA_SET,";
				handle_rc(root, data, m_state.get_rss(), "replica set");
				break;
			case k8s_component::K8S_SERVICES:
				os << "SERVICE,";
				handle_service(root, data);
				break;
			case k8s_component::K8S_DAEMONSETS:
				os << "DAEMON_SET,";
				handle_daemonset(root, data);
				break;
			case k8s_component::K8S_DEPLOYMENTS:
				os << "DEPLOYMENT,";
				handle_deployment(root, data);
				break;
			case k8s_component::K8S_EVENTS:
				os << "EVENT,";
				if(m_event_filter)
				{
					handle_event(root, data);
				}
				break;
			default:
			{
				std::ostringstream eos;
				eos << "Unknown component: " << static_cast<int>(m_type);
				throw sinsp_exception(os.str());
			}
		}
		os << data.m_name << ',' << data.m_uid << ',' << data.m_namespace << ']';
		g_logger.log(os.str(), sinsp_logger::SEV_INFO);
		//g_logger.log(root.toStyledString(), sinsp_logger::SEV_DEBUG);
		m_state.update_cache(m_type);
#ifdef HAS_CAPTURE
		if(enqueue)
		{
			m_state.enqueue_capture_event(root);
		}
#endif
	}
}

void k8s_dispatcher::extract_data(const std::string& json, bool enqueue)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		extract_data(root, enqueue);
	}
	else
	{
		g_logger.log("Bad JSON message received :[" + json + ']', sinsp_logger::SEV_ERROR);
	}
}

void k8s_dispatcher::dispatch()
{
	for (list::iterator it = m_messages.begin(); it != m_messages.end();)
	{
		if(is_ready(*it))
		{
			extract_data(*it, true);
			it = m_messages.erase(it);
		}
		else
		{
			++it;
		}
	}
}

std::string k8s_dispatcher::to_reason_desc(msg_reason reason)
{
	switch (reason)
	{
	case COMPONENT_ADDED:
		return "ADDED";
	case COMPONENT_MODIFIED:
		return "MODIFIED";
	case COMPONENT_DELETED:
		return "DELETED";
	case COMPONENT_ERROR:
		return "ERROR";
	case COMPONENT_UNKNOWN:
		return "UNKNOWN";
	default:
		return "";
	}
}

k8s_dispatcher::msg_reason k8s_dispatcher::to_reason(const std::string& desc)
{
	if(desc == "ADDED") { return COMPONENT_ADDED; }
	else if(desc == "MODIFIED") { return COMPONENT_MODIFIED; }
	else if(desc == "DELETED") { return COMPONENT_DELETED; }
	else if(desc == "ERROR") { return COMPONENT_ERROR; }
	else if(desc == "UNKNOWN") { return COMPONENT_UNKNOWN; }
	throw sinsp_exception(desc);
}
#endif // CYGWING_AGENT
