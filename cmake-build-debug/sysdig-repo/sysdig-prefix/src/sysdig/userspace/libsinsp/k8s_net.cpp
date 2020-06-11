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
// k8s_net.cpp
//
#ifndef CYGWING_AGENT

#ifdef HAS_CAPTURE

#include "k8s_net.h"
#include "k8s_component.h"
#include "k8s_node_handler.h"
#include "k8s_namespace_handler.h"
#include "k8s_pod_handler.h"
#include "k8s_replicationcontroller_handler.h"
#include "k8s_replicaset_handler.h"
#include "k8s_service_handler.h"
#include "k8s_daemonset_handler.h"
#include "k8s_deployment_handler.h"
#include "k8s_event_handler.h"
#include "k8s.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <utility>
#include <memory>


k8s_net::k8s_net(k8s& kube, k8s_state_t& state, const std::string& uri,
	ssl_ptr_t ssl,
	bt_ptr_t bt,
	filter_ptr_t event_filter,
	bool blocking_sockets) : m_state(state),
		m_collector(std::make_shared<collector_t>()),
		m_uri(uri),
		m_ssl(ssl),
		m_bt(bt),
		m_stopped(true),
		m_blocking_sockets(blocking_sockets),
		m_event_filter(event_filter)
{
}

k8s_net::~k8s_net()
{
	cleanup();
}

void k8s_net::cleanup()
{
	stop_watching();
	m_handlers.clear();
}

void k8s_net::watch()
{
	for(auto it = m_handlers.cbegin(); it != m_handlers.cend();)
	{
		k8s_component::type comp_type = it->first;
		if(it->second)
		{
			if(it->second->connection_error())
			{
				if(k8s_component::is_critical(comp_type))
				{
					throw sinsp_exception("K8s: " + k8s_component::get_name(comp_type) + " connection error.");
				}
				else
				{
					g_logger.log("K8s: " + k8s_component::get_name(comp_type) + " connection error, removing component.",
						 sinsp_logger::SEV_WARNING);
					if(m_collector->has(it->second->handler()))
					{
						m_collector->remove(it->second->handler());
					}
					m_handlers.erase(it++);
					g_logger.log("K8s: " + k8s_component::get_name(comp_type) + " removed from watched endpoints.",
						 sinsp_logger::SEV_INFO);
				}
			}
			else
			{
				it->second->collect_data();
				++it;
			}
		}
		else
		{
			g_logger.log("K8s: " + k8s_component::get_name(comp_type) + " handler is null.",
						 sinsp_logger::SEV_WARNING);
			++it;
		}
	}
}

void k8s_net::stop_watching()
{
	if(!m_stopped)
	{
		m_stopped = true;
		m_collector->remove_all();
	}
}

k8s_net::handler_ptr_t k8s_net::get_dependency_handler(const handler_map_t& handlers, const k8s_component::type& component)
{
	switch(component)
	{
		case k8s_component::K8S_NODES:
			return std::make_shared<k8s_dummy_handler>();
		case k8s_component::K8S_NAMESPACES:
			return get_handler(handlers, k8s_component::K8S_NODES);
		case k8s_component::K8S_PODS:
			return get_handler(handlers, k8s_component::K8S_NAMESPACES);
		case k8s_component::K8S_REPLICATIONCONTROLLERS:
			return get_handler(handlers, k8s_component::K8S_PODS);
		case k8s_component::K8S_SERVICES:
			return get_handler(handlers, k8s_component::K8S_PODS);
		case k8s_component::K8S_REPLICASETS:
			return get_handler(handlers, k8s_component::K8S_PODS);
		case k8s_component::K8S_DAEMONSETS:
			return get_handler(handlers, k8s_component::K8S_PODS);
		case k8s_component::K8S_DEPLOYMENTS:
			return get_handler(handlers, k8s_component::K8S_PODS);
		case k8s_component::K8S_EVENTS:
			return std::make_shared<k8s_dummy_handler>();
		case k8s_component::K8S_COMPONENT_COUNT:
		default: break;
	}
	throw sinsp_exception(std::string("Invalid K8s component type:") + std::to_string(component));
}

k8s_net::handler_ptr_t k8s_net::get_dependency_handler(const handler_map_t&  handlers, const k8s_component::type_map::value_type& component)
{
	return get_dependency_handler(handlers, component.first);
}

bool k8s_net::has_dependency(const k8s_component::type_map::value_type& component)
{
	auto it = get_dependency_handler(m_handlers, component);
	return (it && it->is_state_built());
}

k8s_net::handler_ptr_t k8s_net::make_handler(k8s_state_t& state, const k8s_component::type component, bool connect,
											handler_ptr_t dep, collector_ptr_t collector, const std::string& urlstr,
											ssl_ptr_t ssl, bt_ptr_t bt, bool blocking, filter_ptr_t event_filter)
{
	switch(component)
	{
		case k8s_component::K8S_NODES:
			return std::make_shared<k8s_node_handler>(state, dep, collector, urlstr, "1.1", ssl, bt, connect, blocking);
		case k8s_component::K8S_NAMESPACES:
			return std::make_shared<k8s_namespace_handler>(state, dep, collector, urlstr, "1.1", ssl, bt, connect, blocking);
		case k8s_component::K8S_PODS:
			return std::make_shared<k8s_pod_handler>(state, dep, collector, urlstr, "1.1", ssl, bt, connect, blocking);
		case k8s_component::K8S_REPLICATIONCONTROLLERS:
			return std::make_shared<k8s_replicationcontroller_handler>(state, dep, collector, urlstr, "1.1", ssl, bt, connect, blocking);
		case k8s_component::K8S_REPLICASETS:
			return std::make_shared<k8s_replicaset_handler>(state, dep, collector, urlstr, "1.1", ssl, bt, connect, blocking);
		case k8s_component::K8S_SERVICES:
			return  std::make_shared<k8s_service_handler>(state, dep, collector, urlstr, "1.1", ssl, bt, connect, blocking);
		case k8s_component::K8S_DAEMONSETS:
			return  std::make_shared<k8s_daemonset_handler>(state, dep, collector, urlstr, "1.1", ssl, bt, connect, blocking);
		case k8s_component::K8S_DEPLOYMENTS:
			return  std::make_shared<k8s_deployment_handler>(state, dep, collector, urlstr, "1.1", ssl, bt, connect, blocking);
		case k8s_component::K8S_EVENTS:
			return std::make_shared<k8s_event_handler>(state, dep, collector, urlstr, "1.1", ssl, bt, connect, blocking, event_filter);
		case k8s_component::K8S_COMPONENT_COUNT:
		default:
			return nullptr;
	}

	return nullptr;
}

void k8s_net::add_handler(const k8s_component::type_map::value_type& component)
{
	if(!has_handler(component))
	{
		handler_ptr_t handler =
			make_handler(m_state, component.first, true, get_dependency_handler(m_handlers, component),
						 m_collector, m_uri.to_string(), m_ssl, m_bt, m_blocking_sockets, m_event_filter);
		if(handler)
		{
			if(!m_machine_id.empty())
			{
				handler->set_machine_id(m_machine_id);
			}
			else if(handler->name() == "events")
			{
				g_logger.log("K8s machine ID (MAC) is empty - scope may not be available for " + handler->name(),
							 sinsp_logger::SEV_WARNING);
			}
			m_handlers[component.first] = handler;
		}
		else
		{
			std::ostringstream os;
			os << "K8s: invalid component type encountered while creating handler: " <<
				component.second << " (" <<
				std::to_string(component.first) << ')';
			if(k8s_component::is_critical(component))
			{
				throw sinsp_exception(os.str());
			}
			else
			{
				g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
			}
		}
		g_logger.log("K8s: created " + k8s_component::get_name(component) + " handler.", sinsp_logger::SEV_INFO);
	}
	else
	{
		g_logger.log("K8s: component " + k8s_component::get_name(component) + " already exists.",
					 sinsp_logger::SEV_TRACE);
	}
}
#else // !HAS_CAPTURE

#include "k8s_component.h"
#include "k8s_node_handler.h"
#include "k8s_namespace_handler.h"
#include "k8s_pod_handler.h"
#include "k8s_replicationcontroller_handler.h"
#include "k8s_replicaset_handler.h"
#include "k8s_service_handler.h"
#include "k8s_daemonset_handler.h"
#include "k8s_deployment_handler.h"
#include "k8s_event_handler.h"

namespace k8s_net
{
	k8s_handler::ptr_t make_handler(k8s_state_t& state, const k8s_component::type component, bool /*connect*/)
	{
		switch(component)
		{
			case k8s_component::K8S_NODES:
				return std::make_shared<k8s_node_handler>(state);
			case k8s_component::K8S_NAMESPACES:
				return std::make_shared<k8s_namespace_handler>(state);
			case k8s_component::K8S_PODS:
				return std::make_shared<k8s_pod_handler>(state);
			case k8s_component::K8S_REPLICATIONCONTROLLERS:
				return std::make_shared<k8s_replicationcontroller_handler>(state);
			case k8s_component::K8S_REPLICASETS:
				return std::make_shared<k8s_replicaset_handler>(state);
			case k8s_component::K8S_SERVICES:
				return  std::make_shared<k8s_service_handler>(state);
			case k8s_component::K8S_DAEMONSETS:
				return  std::make_shared<k8s_daemonset_handler>(state);
			case k8s_component::K8S_DEPLOYMENTS:
				return  std::make_shared<k8s_deployment_handler>(state);
			case k8s_component::K8S_EVENTS:
				return std::make_shared<k8s_event_handler>(state);
			case k8s_component::K8S_COMPONENT_COUNT:
			default:
				return nullptr;
		}
		return nullptr;
	}
}

#endif // HAS_CAPTURE
#endif // CYGWING_AGENT
