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
// k8s_pod_handler.cpp
//
#ifndef CYGWING_AGENT

#include "k8s_pod_handler.h"
#include "sinsp.h"
#include "sinsp_int.h"

// filters normalize state and event JSONs, so they can be processed generically:
// event is turned into a single-entry array, state is turned into an array of ADDED events

std::string k8s_pod_handler::EVENT_FILTER =
	"{"
	" type: .type,"
	" apiVersion: .object.apiVersion,"
	" kind: .object.kind,"
	" items:"
	" ["
	"  .object |"
	"  {"
	"   namespace: .metadata.namespace,"
	"   name: .metadata.name,"
	"   uid: .metadata.uid,"
	"   timestamp: .metadata.creationTimestamp,"
	"   nodeName: .spec.nodeName,"
	"   hostIP: .status.hostIP,"
	"   podIP: .status.podIP,"
	"   phase: .status.phase,"
	"   containers: .spec.containers,"
	"   containerStatuses: .status.containerStatuses,"
	"   initContainerStatuses: .status.initContainerStatuses,"
	"   labels: .metadata.labels"
	"  }"
	" ]"
	"}";

std::string k8s_pod_handler::STATE_FILTER =
	"{"
	" type: \"ADDED\","
	" apiVersion: .apiVersion,"
	" kind: \"Pod\", "
	" items:"
	" ["
	"  .items[] | "
	"  {"
	"   namespace: .metadata.namespace,"
	"   name: .metadata.name,"
	"   uid: .metadata.uid,"
	"   timestamp: .metadata.creationTimestamp,"
	"   nodeName: .spec.nodeName,"
	"   hostIP: .status.hostIP,"
	"   podIP: .status.podIP,"
	"   phase: .status.phase,"
	"   containers: .spec.containers,"
	"   containerStatuses: .status.containerStatuses,"
	"   initContainerStatuses: .status.initContainerStatuses,"
	"   labels: .metadata.labels,"
	"   }"
	" ]"
	"}";

k8s_pod_handler::k8s_pod_handler(k8s_state_t& state
#ifdef HAS_CAPTURE
	,ptr_t dependency_handler
	,collector_ptr_t collector
	,std::string url
	,const std::string& http_version
	,ssl_ptr_t ssl
	,bt_ptr_t bt
	,bool connect
	,bool blocking_socket
#endif // HAS_CAPTURE
	):
		k8s_handler("k8s_pod_handler", true,
#ifdef HAS_CAPTURE
					url, "/api/v1/pods?fieldSelector=status.phase!=Failed,status.phase!=Unknown,status.phase!=Succeeded",
					STATE_FILTER, EVENT_FILTER, "", collector,
					http_version, 1000L, ssl, bt, true,
					connect, dependency_handler, blocking_socket,
#endif // HAS_CAPTURE
					~0, &state)
{
}

k8s_pod_handler::~k8s_pod_handler()
{
}

std::vector<std::string> k8s_pod_handler::extract_pod_container_ids(const Json::Value& item)
{
	std::vector<std::string> container_list;

	const Json::Value& containers = item["containerStatuses"];
	if(!containers.isNull())
	{
		for (auto& container : containers)
		{
			const Json::Value& container_id = container["containerID"];
			if(!container_id.isNull())
			{
				container_list.emplace_back(container_id.asString());
			}
		}
	}

	const Json::Value& initContainers = item["initContainerStatuses"];
	if(!initContainers.isNull())
	{
		for (auto& container : initContainers)
		{
			const Json::Value& container_id = container["containerID"];
			if(!container_id.isNull())
			{
				container_list.emplace_back(container_id.asString());
			}
		}
	}

	return container_list;
}

k8s_container::list k8s_pod_handler::extract_pod_containers(const Json::Value& item)
{
	k8s_container::list ext_containers;
	// Not looking for init containers here because this appears
	// to only be used by the k8s_service_handler for named port
	// resolution. Init containers can't have service ports.
	const Json::Value& containers = item["containers"];
	if(!containers.isNull())
	{
		for (auto& container : containers)
		{
			std::string cont_name;
			const Json::Value& name = container["name"];
			if(!name.isNull()) { cont_name = name.asString(); }
			else { return ext_containers; }
			k8s_container::port_list cont_ports;
			const Json::Value& ports = container["ports"];
			for(const auto& port : ports)
			{
				k8s_container::port cont_port;
				const Json::Value& name = port["name"];
				if(!name.isNull())
				{
					cont_port.set_name(name.asString());
				}
				const Json::Value& cport = port["containerPort"];
				if(!cport.isNull())
				{
					cont_port.set_port(cport.asUInt());
				}
				else
				{
					g_logger.log("Port not found, setting value to 0", sinsp_logger::SEV_WARNING);
					cont_port.set_port(0);
				}
				const Json::Value& protocol = port["protocol"];
				if(!protocol.isNull())
				{
					cont_port.set_protocol(protocol.asString());
				}
				else
				{
					std::string port_name = name.isNull() ? "[NO NAME]" : name.asString();
					g_logger.log("Protocol not found for port: " + port_name, sinsp_logger::SEV_WARNING);
				}
				cont_ports.push_back(cont_port);
			}
			ext_containers.emplace_back(k8s_container(cont_name, cont_ports));
		}
	}
	return ext_containers;
}

void k8s_pod_handler::extract_pod_data(const Json::Value& item, k8s_pod_t& pod)
{
	const Json::Value& node_name = item["nodeName"];
	if(!node_name.isNull())
	{
		std::string nn = node_name.asString();
		if(!nn.empty())
		{
			pod.set_node_name(nn);
		}
	}
	const Json::Value& host_ip = item["hostIP"];
	if(!host_ip.isNull())
	{
		std::string hip = host_ip.asString();
		if(!hip.empty())
		{
			pod.set_host_ip(hip);
		}
	}
	const Json::Value& pod_ip = item["podIP"];
	if(!pod_ip.isNull())
	{
		std::string pip = pod_ip.asString();
		if(!pip.empty())
		{
			pod.set_internal_ip(pip);
		}
	}
}

size_t k8s_pod_handler::extract_pod_restart_count(const Json::Value& item)
{
	size_t restart_count = 0;
	const Json::Value& container_statuses = item["containerStatuses"];
	if(!container_statuses.isNull())
	{
		for (auto& status : container_statuses)
		{
			const Json::Value& rc = status["restartCount"];
			if(!rc.isNull() && rc.isInt())
			{
				restart_count += rc.asInt();
			}
		}
	}
	return restart_count;
}

bool k8s_pod_handler::handle_component(const Json::Value& json, const msg_data* data)
{
	if(data)
	{
		if(m_state)
		{
			if((data->m_reason == k8s_component::COMPONENT_ADDED) ||
			   (data->m_reason == k8s_component::COMPONENT_MODIFIED))
			{
				k8s_pod_t& pod =
					m_state->get_component<k8s_pods, k8s_pod_t>(m_state->get_pods(),
																  data->m_name, data->m_uid, data->m_namespace);
				k8s_pair_list entries = k8s_component::extract_object(json, "labels");
				if(entries.size() > 0)
				{
					pod.set_labels(std::move(entries));
				}
				k8s_pod_t::container_id_list container_ids = extract_pod_container_ids(json);
				k8s_container::list containers = extract_pod_containers(json);
				extract_pod_data(json, pod);
				pod.set_restart_count(extract_pod_restart_count(json));
				pod.set_container_ids(std::move(container_ids));
				pod.set_containers(std::move(containers));
			}
			else if(data->m_reason == k8s_component::COMPONENT_DELETED)
			{
				if(!m_state->delete_component(m_state->get_pods(), data->m_uid))
				{
					log_not_found(*data);
					return false;
				}
			}
		}
		else if(data->m_reason != k8s_component::COMPONENT_ERROR)
		{
			g_logger.log(std::string("Unsupported K8S " + name() + " event reason: ") +
						 std::to_string(data->m_reason), sinsp_logger::SEV_ERROR);
			return false;
		}
	}
	else
	{
		throw sinsp_exception("K8s node handler: data is null.");
	}
	return true;
}
#endif // CYGWING_AGENT
