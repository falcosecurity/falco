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
// k8s_node_handler.cpp
//
#ifndef CYGWING_AGENT

#include "k8s_node_handler.h"
#include "sinsp.h"
#include "sinsp_int.h"

// filters normalize state and event JSONs, so they can be processed generically:
// event is turned into a single-entry array, state is turned into an array of ADDED events

std::string k8s_node_handler::EVENT_FILTER =
	"{"
	" type: .type,"
	" apiVersion: .object.apiVersion,"
	" kind: .object.kind,"
	" items:"
	" ["
	"  .object |"
	"  {"
	"   name: .metadata.name,"
	"   uid: .metadata.uid,"
	"   timestamp: .metadata.creationTimestamp,"
	"   labels: .metadata.labels,"
	"   addresses: [.status.addresses[].address] | unique"
	"  }"
	" ]"
	"}";

std::string k8s_node_handler::STATE_FILTER =
	"{"
	" type: \"ADDED\","
	" apiVersion: .apiVersion,"
	" kind: \"Node\", "
	" items:"
	" ["
	"  .items[] | "
	"  {"
	"   name: .metadata.name,"
	"   uid: .metadata.uid,"
	"   timestamp: .metadata.creationTimestamp,"
	"   labels: .metadata.labels,"
	"   addresses: [.status.addresses[].address] | unique"
	"   }"
	" ]"
	"}";

k8s_node_handler::k8s_node_handler(k8s_state_t& state
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
		k8s_handler("k8s_node_handler", true,
#ifdef HAS_CAPTURE
					url, "/api/v1/nodes",
					STATE_FILTER, EVENT_FILTER, "", collector,
					http_version, 1000L, ssl, bt, true,
					connect, dependency_handler, blocking_socket,
#endif // HAS_CAPTURE
					~0, &state)
{
}

k8s_node_handler::~k8s_node_handler()
{
}

bool k8s_node_handler::handle_component(const Json::Value& json, const msg_data* data)
{
	if(data)
	{
		if(m_state)
		{
			if((data->m_reason == k8s_component::COMPONENT_ADDED) ||
			   (data->m_reason == k8s_component::COMPONENT_MODIFIED))
			{
				k8s_node_t& node =
					m_state->get_component<k8s_nodes, k8s_node_t>(m_state->get_nodes(),
																  data->m_name, data->m_uid);
				k8s_node_t::host_ip_list addresses;
				k8s_component::extract_string_array(json["addresses"], addresses);
				if(addresses.size() > 0)
				{
					node.set_host_ips(std::move(addresses));
				}
				else
				{
					g_logger.log("K8s Node handler: Can not obtain IP address(es) for node" + data->m_name +
								 '[' + data->m_uid + ']', sinsp_logger::SEV_ERROR);
				}
				k8s_pair_list entries = k8s_component::extract_object(json, "labels");
				if(entries.size() > 0)
				{
					node.set_labels(std::move(entries));
				}
			}
			else if(data->m_reason == k8s_component::COMPONENT_DELETED)
			{
				if(!m_state->delete_component(m_state->get_nodes(), data->m_uid))
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
#endif // CYGWING_AGENT
