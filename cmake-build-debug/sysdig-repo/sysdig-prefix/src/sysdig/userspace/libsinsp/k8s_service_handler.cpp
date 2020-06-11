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
// k8s_service_handler.cpp
//
#ifndef CYGWING_AGENT

#include "k8s_service_handler.h"
#include "sinsp.h"
#include "sinsp_int.h"

// filters normalize state and event JSONs, so they can be processed generically:
// event is turned into a single-entry array, state is turned into an array of ADDED events

std::string k8s_service_handler::EVENT_FILTER =
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
	"   clusterIP: .spec.clusterIP,"
	"   ports: .spec.ports,"
	"   labels: .metadata.labels,"
	"   selector: .spec.selector"
	"  }"
	" ]"
	"}";

std::string k8s_service_handler::STATE_FILTER =
	"{"
	" type: \"ADDED\","
	" apiVersion: .apiVersion,"
	" kind: \"Service\", "
	" items:"
	" ["
	"  .items[] | "
	"  {"
	"   namespace: .metadata.namespace,"
	"   name: .metadata.name,"
	"   uid: .metadata.uid,"
	"   timestamp: .metadata.creationTimestamp,"
	"   clusterIP: .spec.clusterIP,"
	"   ports: .spec.ports,"
	"   labels: .metadata.labels,"
	"   selector: .spec.selector"
	"   }"
	" ]"
	"}";

std::string k8s_service_handler::NULL_FILTER =
	"{"
	" type: \"NONEXISTENT\","
	" apiVersion: .apiVersion,"
	" kind: \"Service\", "
	" items: [ null ]"
	"}";

k8s_service_handler::k8s_service_handler(k8s_state_t& state
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
		k8s_handler("k8s_service_handler", true,
#ifdef HAS_CAPTURE
					url, "/api/v1/services",
					STATE_FILTER, EVENT_FILTER, NULL_FILTER, collector,
					http_version, 1000L, ssl, bt, true,
					connect, dependency_handler, blocking_socket,
#endif // HAS_CAPTURE
					100, // max msgs
					&state)
{
}

k8s_service_handler::~k8s_service_handler()
{
}

void k8s_service_handler::extract_services_data(const Json::Value& json, k8s_service_t& service, const k8s_pods& pods)
{
	if(!json.isNull())
	{
		const Json::Value& cluster_ip = json["clusterIP"];
		if(!cluster_ip.isNull())
		{
			service.set_cluster_ip(cluster_ip.asString());
		}

		k8s_service_t::port_list pl;
		const Json::Value& ports = json["ports"];
		if(!ports.isNull() && ports.isArray())
		{
			for (auto& port : ports)
			{
				k8s_service_t::net_port p;
				const Json::Value& json_port = port["port"];
				if(!json_port.isNull())
				{
					p.m_port = json_port.asUInt();
				}

				const Json::Value& json_protocol = port["protocol"];
				if(!json_protocol.isNull())
				{
					p.m_protocol = json_protocol.asString();
				}

				const Json::Value& json_target_port = port["targetPort"];
				if(!json_target_port.isNull())
				{
					if(json_target_port.isIntegral())
					{
						p.m_target_port = json_target_port.asUInt();
					}
					else if(json_target_port.isString())
					{
						std::string port_name = json_target_port.asString();
						std::vector<const k8s_pod_t*> pod_subset = service.get_selected_pods(pods);
						p.m_target_port = 0;
						for(const auto& pod : pod_subset)
						{
							const k8s_container::list& containers = pod->get_containers();
							for(const auto& container : containers)
							{
								const k8s_container::port* container_port = container.get_port(port_name);
								if(container_port)
								{
									g_logger.log("K8s: found port for service [" + service.get_name() + "], "
												 "container [" + container.get_name() + ']',
												 sinsp_logger::SEV_DEBUG);
									p.m_target_port = container_port->get_port();
									break;
								}
								else
								{
									g_logger.log("K8s: error while trying to determine port for service [" + service.get_name() + "]: "
												"no ports found for container [" + container.get_name() + "]", sinsp_logger::SEV_ERROR);
									p.m_target_port = 0;
								}
							}
						}
					}
					else
					{
						g_logger.log("Port of unknown or unsupported type.", sinsp_logger::SEV_ERROR);
						p.m_target_port = 0;
					}
				}

				const Json::Value& json_node_port = port["nodePort"];
				if(!json_node_port.isNull())
				{
					p.m_node_port = json_node_port.asUInt();
				}

				if(p.m_port && p.m_target_port)
				{
					pl.push_back(p);
				}
			}
		}

		if(pl.size())
		{
			service.set_port_list(std::move(pl));
		}
	}
	else
	{
		g_logger.log("Error while extracting data for service [" + service.get_name() + "]: "
					" JSON is null.", sinsp_logger::SEV_ERROR);
	}
}

bool k8s_service_handler::handle_component(const Json::Value& json, const msg_data* data)
{
	if(data)
	{
		if(m_state)
		{
			if((data->m_reason == k8s_component::COMPONENT_ADDED) ||
			   (data->m_reason == k8s_component::COMPONENT_MODIFIED))
			{
				k8s_service_t& service =
					m_state->get_component<k8s_services, k8s_service_t>(m_state->get_services(),
																		data->m_name, data->m_uid, data->m_namespace);
				k8s_pair_list entries = k8s_component::extract_object(json, "labels");
				if(entries.size() > 0)
				{
					service.set_labels(std::move(entries));
				}
				entries = k8s_component::extract_object(json, "selector");
				if(entries.size() > 0)
				{
					service.set_selectors(std::move(entries));
				}
				extract_services_data(json, service, m_state->get_pods());
			}
			else if(data->m_reason == k8s_component::COMPONENT_DELETED)
			{
				if(!m_state->delete_component(m_state->get_services(), data->m_uid))
				{
					log_not_found(*data);
					return false;
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
			throw sinsp_exception("K8s node handler: state is null.");
		}
	}
	else
	{
		throw sinsp_exception("K8s node handler: data is null.");
	}
	return true;
}
#endif