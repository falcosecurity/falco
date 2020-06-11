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

#include "k8s_state.h"
#include "k8s_pod_handler.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <iostream>

//
// state
//

const std::string k8s_state_t::m_docker_prefix = "docker://";
const std::string k8s_state_t::m_rkt_prefix = "rkt://";
const std::string k8s_state_t::m_containerd_prefix = "containerd://";
const std::string k8s_state_t::m_crio_prefix = "cri-o://";
const unsigned    k8s_state_t::m_id_length = 12u;

k8s_state_t::k8s_state_t(bool is_captured, int capture_version):
	m_is_captured(is_captured),
	m_capture_version(capture_version)
{
}

// state/pods

void k8s_state_t::update_pod(k8s_pod_t& pod, const Json::Value& item)
{
	k8s_pod_t::container_id_list container_ids = k8s_pod_handler::extract_pod_container_ids(item);
	k8s_container::list containers = k8s_pod_handler::extract_pod_containers(item);
	k8s_pod_handler::extract_pod_data(item, pod);
	pod.set_restart_count(k8s_pod_handler::extract_pod_restart_count(item));
	pod.set_container_ids(std::move(container_ids));
	pod.set_containers(std::move(containers));
}

void k8s_state_t::cache_pod(container_pod_map& map, const std::string& id, const k8s_pod_t* pod)
{
	ASSERT(pod);
	ASSERT(!pod->get_name().empty());
	std::string::size_type pos = id.find(m_docker_prefix);
	if(pos == 0)
	{
		map[id.substr(m_docker_prefix.size(), m_id_length)] = pod;
		return;
	}
	pos = id.find(m_rkt_prefix);
	if(pos == 0)
	{
		map[id.substr(m_rkt_prefix.size())] = pod;
		return;
	}
	pos = id.find(m_containerd_prefix);
	if(pos == 0)
	{
		map[id.substr(m_containerd_prefix.size(), m_id_length)] = pod;
		return;
	}
	pos = id.find(m_crio_prefix);
	if(pos == 0)
	{
		map[id.substr(m_crio_prefix.size(), m_id_length)] = pod;
		return;
	}
	throw sinsp_exception("Invalid container ID (expected one of: '" + m_docker_prefix +
						 "{ID}', '" + m_rkt_prefix + "{ID}', '" + m_containerd_prefix +
						 "{ID}', '" + m_crio_prefix + "{ID}'): " + id);
}

bool k8s_state_t::has_pod(k8s_pod_t& pod)
{
	for(const auto& p : m_pods)
	{
		if(p == pod) { return true; }
	}
	return false;
}

// state/events

void k8s_state_t::update_event(k8s_event_t& evt, const Json::Value& item)
{
	if(!item.isNull())
	{
		evt.update(item, *this);
	}
	else
	{
		g_logger.log("NULL K8s event received.", sinsp_logger::SEV_WARNING);
	}
}

// state/general

void k8s_state_t::replace_items(k8s_component::type t, const std::string& name, const std::vector<k8s_pair_t>&& items)
{
	switch (t)
	{
	case k8s_component::K8S_NODES:
		if(name == "labels")
		{
			m_nodes.back().m_labels = std::move(items);
			return;
		}
		break;

	case k8s_component::K8S_NAMESPACES:
		if(name == "labels")
		{
			m_namespaces.back().m_labels = std::move(items);
			return;
		}
		break;

	case k8s_component::K8S_PODS:
		if(name == "labels")
		{
			m_pods.back().m_labels = std::move(items);
			return;
		}
		break;

	case k8s_component::K8S_REPLICATIONCONTROLLERS:
		if(name == "labels")
		{
			m_controllers.back().m_labels = std::move(items);
			return;
		}
		else if(name == "selector")
		{
			m_controllers.back().m_selectors = std::move(items);
			return;
		}
		break;

	case k8s_component::K8S_REPLICASETS:
		if(name == "labels")
		{
			m_replicasets.back().m_labels = std::move(items);
			return;
		}
		else if(name == "selector")
		{
			m_replicasets.back().m_selectors = std::move(items);
			return;
		}
		break;

	case k8s_component::K8S_SERVICES:
		if(name == "labels")
		{
			m_services.back().m_labels = std::move(items);
			return;
		}
		else if(name == "selector")
		{
			m_services.back().m_selectors = std::move(items);
			return;
		}
		break;

	case k8s_component::K8S_DEPLOYMENTS:
		if(name == "labels")
		{
			m_deployments.back().m_labels = std::move(items);
			return;
		}
		else if(name == "selector")
		{
			m_deployments.back().m_selectors = std::move(items);
			return;
		}
		break;

	case k8s_component::K8S_DAEMONSETS:
		if(name == "labels")
		{
			m_daemonsets.back().m_labels = std::move(items);
			return;
		}
		else if(name == "selector")
		{
			m_daemonsets.back().m_selectors = std::move(items);
			return;
		}
		break;

	case k8s_component::K8S_EVENTS:
		return;

	case k8s_component::K8S_COMPONENT_COUNT:
	default:
		break;
	}

	std::ostringstream os;
	os << "Unknown component type " << static_cast<int>(t) <<
		" or object name " << name;
	throw sinsp_exception(os.str().c_str());
}

k8s_component& k8s_state_t::add_common_single_value(k8s_component::type component, const std::string& name, const std::string& uid, const std::string& ns)
{
	switch (component)
	{
		case k8s_component::K8S_NODES:
			return get_component<k8s_nodes, k8s_node_t>(m_nodes, name, uid, ns);

		case k8s_component::K8S_NAMESPACES:
			return get_component<k8s_namespaces, k8s_ns_t>(m_namespaces, name, uid, ns);

		case k8s_component::K8S_PODS:
			return get_component<k8s_pods, k8s_pod_t>(m_pods, name, uid, ns);

		case k8s_component::K8S_REPLICATIONCONTROLLERS:
			return get_component<k8s_controllers, k8s_rc_t>(m_controllers, name, uid, ns);

		case k8s_component::K8S_REPLICASETS:
			return get_component<k8s_replicasets, k8s_rs_t>(m_replicasets, name, uid, ns);

		case k8s_component::K8S_SERVICES:
			return get_component<k8s_services, k8s_service_t>(m_services, name, uid, ns);

		case k8s_component::K8S_DAEMONSETS:
			return get_component<k8s_daemonsets, k8s_daemonset_t>(m_daemonsets, name, uid, ns);

		case k8s_component::K8S_DEPLOYMENTS:
			return get_component<k8s_deployments, k8s_deployment_t>(m_deployments, name, uid, ns);

		case k8s_component::K8S_EVENTS:
			return get_component<k8s_events, k8s_event_t>(m_events, name, uid, ns);

		case k8s_component::K8S_COMPONENT_COUNT:
		default:
			break;
	}

	std::ostringstream os;
	os << "Unknown component: " << component;
	throw sinsp_exception(os.str());
}

k8s_node_t* k8s_state_t::get_node(const std::string& uid)
{
	for (auto& node : m_nodes)
	{
		if(node.get_uid() == uid)
		{
			return &node;
		}
	}

	return nullptr;
}

void k8s_state_t::clear(k8s_component::type type)
{
	if(type == k8s_component::K8S_COMPONENT_COUNT)
	{
		m_namespaces.clear();
		m_nodes.clear();
		m_pods.clear();
		m_controllers.clear();
		m_services.clear();
	}
	else
	{
		switch (type)
		{
		case k8s_component::K8S_NODES:
			m_nodes.clear();
			break;
		case k8s_component::K8S_NAMESPACES:
			m_namespaces.clear();
			break;
		case k8s_component::K8S_PODS:
			m_pods.clear();
			break;
		case k8s_component::K8S_REPLICATIONCONTROLLERS:
			m_controllers.clear();
			break;
		case k8s_component::K8S_REPLICASETS:
			m_replicasets.clear();
			break;
		case k8s_component::K8S_SERVICES:
			m_services.clear();
			break;
		case k8s_component::K8S_DAEMONSETS:
			m_daemonsets.clear();
			break;
		case k8s_component::K8S_DEPLOYMENTS:
			m_deployments.clear();
			break;
		case k8s_component::K8S_EVENTS:
			m_events.clear();
			break;
		case k8s_component::K8S_COMPONENT_COUNT:
		default:
			break;
		}
	}
}

// state/caching

void k8s_state_t::update_cache(const k8s_component::type_map::key_type& component)
{
#ifndef HAS_ANALYZER
	switch (component)
	{
		case k8s_component::K8S_NAMESPACES:
		{
			const k8s_namespaces& nspaces = get_namespaces();
			k8s_state_t::namespace_map& ns_map = get_namespace_map();
			ns_map.clear();
			for(const auto& ns : nspaces)
			{
				std::string ns_name = ns.get_name();
				if(!is_component_cached(ns_map, ns_name, &ns))
				{
					cache_component(ns_map, ns_name, &ns);
				}
				else
				{
					g_logger.log("Attempt to cache already cached NAMESPACE: " + ns_name, sinsp_logger::SEV_ERROR);
				}
			}
		}
		break;

		case k8s_component::K8S_PODS:
		{
			const k8s_pods& pods = get_pods();
			k8s_state_t::container_pod_map& container_pod_map = get_container_pod_map();
			container_pod_map.clear();
			for(const auto& pod : pods)
			{
				const k8s_pod_t::container_id_list& c_ids = pod.get_container_ids();
				for(const auto& c_id : c_ids)
				{
					if(!is_component_cached(container_pod_map, c_id, &pod))
					{
						cache_pod(container_pod_map, c_id, &pod);
					}
					else
					{
						g_logger.log("Attempt to cache already cached POD: " + c_id, sinsp_logger::SEV_ERROR);
					}
				}
			}
		}
		break;

		case k8s_component::K8S_REPLICATIONCONTROLLERS:
		{
			const k8s_controllers& rcs = get_rcs();
			const k8s_pods& pods = get_pods();
			k8s_state_t::pod_rc_map& pod_ctrl_map = get_pod_rc_map();
			pod_ctrl_map.clear();
			for(const auto& rc : rcs)
			{
				std::vector<const k8s_pod_t*> pod_subset = rc.get_selected_pods(pods);
				for(auto& pod : pod_subset)
				{
					const std::string& pod_uid = pod->get_uid();
					if(!is_component_cached(pod_ctrl_map, pod_uid, &rc))
					{
						cache_component(pod_ctrl_map, pod_uid, &rc);
					}
					else
					{
						g_logger.log("Attempt to cache already cached REPLICATION CONTROLLER: " + pod_uid, sinsp_logger::SEV_ERROR);
					}
				}
			}
		}
		break;

		case k8s_component::K8S_REPLICASETS:
		{
			const k8s_replicasets& rss = get_rss();
			const k8s_pods& pods = get_pods();
			k8s_state_t::pod_rs_map& pod_rset_map = get_pod_rs_map();
			pod_rset_map.clear();
			for(const auto& rs : rss)
			{
				std::vector<const k8s_pod_t*> pod_subset = rs.get_selected_pods(pods);
				for(auto& pod : pod_subset)
				{
					const std::string& pod_uid = pod->get_uid();
					if(!is_component_cached(pod_rset_map, pod_uid, &rs))
					{
						cache_component(pod_rset_map, pod_uid, &rs);
					}
					else
					{
						g_logger.log("Attempt to cache already cached REPLICA SET: " + pod_uid, sinsp_logger::SEV_ERROR);
					}
				}
			}
		}
		break;

		case k8s_component::K8S_SERVICES:
		{
			const k8s_services& services = get_services();
			const k8s_pods& pods = get_pods();
			k8s_state_t::pod_service_map& pod_svc_map = get_pod_service_map();
			pod_svc_map.clear();
			for(const auto& service : services)
			{
				std::vector<const k8s_pod_t*> pod_subset = service.get_selected_pods(pods);
				for(auto& pod : pod_subset)
				{
					const std::string& pod_uid = pod->get_uid();
					if(!is_component_cached(pod_svc_map, pod_uid, &service))
					{
						cache_component(pod_svc_map, pod_uid, &service);
					}
					else
					{
						g_logger.log("Attempt to cache already cached SERVICE: " + pod_uid, sinsp_logger::SEV_ERROR);
					}
				}
			}
		}
		break;

		case k8s_component::K8S_DAEMONSETS:
		{
			// TODO
			/*const k8s_daemonsets& daemonsets = get_daemonsets();
			const k8s_pods& pods = get_pods();
			k8s_state_t::pod_daemonset_map& pod_svc_map = get_pod_daemonset_map();
			pod_svc_map.clear();
			for(const auto& daemonset : daemonsets)
			{
				std::vector<const k8s_pod_t*> pod_subset = daemonset.get_selected_pods(pods);
				for(auto& pod : pod_subset)
				{
					const std::string& pod_uid = pod->get_uid();
					if(!is_component_cached(pod_svc_map, pod_uid, &daemonset))
					{
						cache_component(pod_svc_map, pod_uid, &daemonset);
					}
					else
					{
						g_logger.log("Attempt to cache already cached SERVICE: " + pod_uid, sinsp_logger::SEV_ERROR);
					}
				}
			}*/
		}
		break;

		case k8s_component::K8S_DEPLOYMENTS:
		{
			const k8s_deployments& deployments = get_deployments();
			const k8s_pods& pods = get_pods();
			k8s_state_t::pod_deployment_map& pod_deployment_map = get_pod_deployment_map();
			pod_deployment_map.clear();
			for(const auto& deployment : deployments)
			{
				std::vector<const k8s_pod_t*> pod_subset = deployment.get_selected_pods(pods);
				for(auto& pod : pod_subset)
				{
					const std::string& pod_uid = pod->get_uid();
					if(!is_component_cached(pod_deployment_map, pod_uid, &deployment))
					{
						cache_component(pod_deployment_map, pod_uid, &deployment);
					}
					else
					{
						g_logger.log("Attempt to cache already cached Deployment: " + pod_uid, sinsp_logger::SEV_ERROR);
					}
				}
			}
		}
		break;

		default: return;
	}
#endif // HAS_ANALYZER
}

k8s_component::type k8s_state_t::component_from_json(const Json::Value& item)
{
	const Json::Value& kind = item["kind"];
	if(kind.isNull() || !kind.isString())
	{
		throw sinsp_exception("Component kind not found in JSON.");
	}
	std::string comp = kind.asString();
	if(comp == "Node")
	{
		return k8s_component::K8S_NODES;
	}
	else if(comp == "Namespace")
	{
		return k8s_component::K8S_NAMESPACES;
	}
	else if(comp == "Pod")
	{
		return k8s_component::K8S_PODS;
	}
	else if(comp == "ReplicationController")
	{
		return k8s_component::K8S_REPLICATIONCONTROLLERS;
	}
	else if(comp == "ReplicaSet")
	{
		return k8s_component::K8S_REPLICASETS;
	}
	else if(comp == "Service")
	{
		return k8s_component::K8S_SERVICES;
	}
	else if(comp == "DaemonSet")
	{
		return k8s_component::K8S_DAEMONSETS;
	}
	else if(comp == "Deployment")
	{
		return k8s_component::K8S_DEPLOYMENTS;
	}
	else if(comp == "Event")
	{
		return k8s_component::K8S_EVENTS;
	}

	throw sinsp_exception("Unknown component kind:" + comp);
}

const k8s_component* k8s_state_t::get_component(const std::string& uid, std::string* t) const
{
	component_map_t::const_iterator it = m_component_map.find(uid);
	if(it != m_component_map.end())
	{
		switch(it->second)
		{
		case k8s_component::K8S_NODES:
			if(t) { *t = "node"; }
			return get_component<k8s_nodes, k8s_node_t>(m_nodes, uid);
			break;
		case k8s_component::K8S_NAMESPACES:
			if(t) { *t = "namespace"; }
			return get_component<k8s_namespaces, k8s_ns_t>(m_namespaces, uid);
			break;
		case k8s_component::K8S_PODS:
			if(t) { *t = "pod"; }
			return get_component<k8s_pods, k8s_pod_t>(m_pods, uid);
			break;
		case k8s_component::K8S_REPLICATIONCONTROLLERS:
			if(t) { *t = "replicationController"; }
			return get_component<k8s_controllers, k8s_rc_t>(m_controllers, uid);
			break;
		case k8s_component::K8S_REPLICASETS:
			if(t) { *t = "replicaSet"; }
			return get_component<k8s_replicasets, k8s_rs_t>(m_replicasets, uid);
			break;
		case k8s_component::K8S_SERVICES:
			if(t) { *t = "service"; }
			return get_component<k8s_services, k8s_service_t>(m_services, uid);
			break;
		case k8s_component::K8S_DAEMONSETS:
			if(t) { *t = "daemonSet"; }
			return get_component<k8s_daemonsets, k8s_daemonset_t>(m_daemonsets, uid);
			break;
		case k8s_component::K8S_DEPLOYMENTS:
			if(t) { *t = "deployment"; }
			return get_component<k8s_deployments, k8s_deployment_t>(m_deployments, uid);
			break;
		case k8s_component::K8S_EVENTS:
			if(t) { *t = "event"; }
			return get_component<k8s_events, k8s_event_t>(m_events, uid);
			break;
		default:
			if(t) { t->clear(); }
			return nullptr;
		}
	}
	return nullptr;
}

#ifdef HAS_CAPTURE
void k8s_state_t::enqueue_capture_event(const Json::Value& item)
{
	if(m_is_captured)
	{
		std::string json;
		if(m_capture_version == k8s_state_t::CAPTURE_VERSION_1)
		{
			json = Json::FastWriter().write(extract_capture_data(item));
		}
		else if(m_capture_version == k8s_state_t::CAPTURE_VERSION_2)
		{
			json = Json::FastWriter().write(item);
		}
		else
		{
			throw sinsp_exception(std::string("K8s : invalid capture version (") +
								  std::to_string(m_capture_version) + ')');
		}
		m_capture_events.emplace_back(json);
	}
}

std::string k8s_state_t::dequeue_capture_event()
{
	if(!m_capture_events.size())
	{
		throw sinsp_exception("Invalid event dequeue request.");
	}
	std::string ev = m_capture_events.front();
	m_capture_events.pop_front();
	return ev;
}
#endif // HAS_CAPTURE

Json::Value k8s_state_t::extract_capture_data(const Json::Value& item)
{
	Json::Value cap_item;

#ifdef HAS_CAPTURE
	k8s_component::type component = component_from_json(item);

	Json::Value ver = item["apiVersion"];
	if(!ver.isNull() && ver.isString())
	{
		cap_item["apiVersion"] = ver.asString();
	}
	else
	{
		throw sinsp_exception("K8S capture: API version not provided.");
	}

	Json::Value type = item["type"];
	if(!type.isNull() && type.isString())
	{
		cap_item["type"] = type.asString();
	}
	else
	{
		throw sinsp_exception("K8S capture: event type not provided.");
	}

	Json::Value kind = item["kind"];
	if(!kind.isNull() && kind.isString())
	{
		cap_item["kind"] = kind.asString();
	}
	else
	{
		throw sinsp_exception("K8S capture: component kind not provided.");
	}
	const Json::Value& object = item["object"];
	if(object.isNull())
	{
		throw sinsp_exception("K8S capture: object not found.");
	}

	cap_item["object"] = Json::Value();
	Json::Value& cap_object = cap_item["object"];
	cap_object["metadata"] = Json::Value();
	Json::Value& cap_metadata = cap_object["metadata"];

	const Json::Value& metadata = object["metadata"];
	if(metadata.isNull())
	{
		throw sinsp_exception("K8S capture: object metadata not found.");
	}
	else
	{
		Json::Value ns = metadata["namespace"];
		if(!ns.isNull())
		{
			cap_metadata["namespace"] = ns.asString();
		}
		cap_metadata["name"] = metadata["name"].asString();
		cap_metadata["uid"] = metadata["uid"].asString();

		Json::Value labels = metadata["labels"];
		if(!labels.isNull())
		{
			cap_metadata["labels"] = labels;
		}
	}

	Json::Value spec = object["spec"];
	if(spec.isNull())
	{
		throw sinsp_exception("K8S capture: object spec not found.");
	}
	else
	{
		Json::Value selector = spec["selector"];
		if(!selector.isNull())
		{
			cap_object["spec"] = Json::Value();
			Json::Value& cap_spec = cap_object["spec"];
			cap_spec["selector"] = std::move(selector);
		}
	}

	Json::Value status = object["status"];
	if(status.isNull())
	{
		throw sinsp_exception("K8S capture: object status not found.");
	}

	switch(component)
	{
	case k8s_component::K8S_NAMESPACES:
		break;

	case k8s_component::K8S_NODES:
		{
			cap_object["status"] = Json::Value();
			Json::Value& cap_status = cap_object["status"];
			cap_object["status"] = Json::Value();
			cap_status["addresses"] = status["addresses"];
		}
		break;

	case k8s_component::K8S_PODS:
		{
			cap_object["spec"] = Json::Value();
			Json::Value& cap_spec = cap_object["spec"];
			const Json::Value& node_name = spec["nodeName"];
			if(!node_name.isNull())
			{
				cap_spec["nodeName"] = node_name.asString();
			}

			cap_object["status"] = Json::Value();
			Json::Value& cap_status = cap_object["status"];
			const Json::Value& host_ip = status["hostIP"];
			if(!host_ip.isNull())
			{
				cap_status["hostIP"] = host_ip.asString();
			}
			const Json::Value& pod_ip = status["podIP"];
			if(!pod_ip.isNull())
			{
				cap_status["podIP"] = pod_ip.asString();
			}

			if(status.isMember("containerStatuses") && status["containerStatuses"].isArray())
			{
				for(const auto& c_status : status["containerStatuses"])
				{
					Json::Value new_status;
					new_status["containerID"] = c_status["containerID"];
					new_status["restartCount"] = c_status["restartCount"];
					cap_status["containerStatuses"].append(new_status);
				}
			}
		}
		break;

	case k8s_component::K8S_SERVICES:
		{
			cap_object["spec"] = Json::Value();
			Json::Value& cap_spec = cap_object["spec"];
			cap_spec["clusterIP"] = spec["clusterIP"].asString();
			cap_spec["ports"] = spec["ports"];
		}
		break;

	case k8s_component::K8S_REPLICATIONCONTROLLERS:
		break;

	case k8s_component::K8S_REPLICASETS:
		break;

	case k8s_component::K8S_DAEMONSETS:
		break;

	case k8s_component::K8S_DEPLOYMENTS:
		break;

	case k8s_component::K8S_EVENTS:
		break;

	default: break;
	}
	std::ostringstream os;
	std::string nspace;
	if(cap_metadata.isMember("namespace"))
	{
		nspace = cap_metadata["namespace"].asString();
	}
	os << "Capture: [" << cap_item["type"].asString() << ',' << cap_item["kind"].asString() << ',' <<
				cap_metadata["name"].asString() << ',' << cap_metadata["uid"].asString() << ',' << nspace << ']';
	g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
	//g_logger.log(item.toStyledString(), sinsp_logger::SEV_DEBUG);
	//g_logger.log(cap_item.toStyledString(), sinsp_logger::SEV_DEBUG);

#endif // HAS_CAPTURE

	return cap_item;
}
#endif // CYGWING_AGENT

