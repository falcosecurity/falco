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
// k8s.cpp
//
#ifndef CYGWING_AGENT

#include "k8s.h"
#include "k8s_component.h"
#include "k8s_dispatcher.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <utility>
#include <memory>
#include <algorithm>
#include <iostream>

k8s_component::type_map k8s::m_components;

k8s::k8s(const std::string& uri, bool is_captured,
#ifdef HAS_CAPTURE
		ssl_ptr_t ssl,
		bt_ptr_t bt,
		bool block,
#endif // HAS_CAPTURE
		filter_ptr_t event_filter,
		ext_list_ptr_t extensions,
		bool events_only) :
		m_state(is_captured),
		m_event_filter(event_filter)
#ifdef HAS_CAPTURE
		,m_net(uri.empty() ?
			   nullptr : new k8s_net(*this, m_state, uri, ssl, bt, event_filter, block))
#endif
{
	g_logger.log(std::string("Creating K8s object for [" +
							 (uri.empty() ? std::string("capture replay") : uri) + ']'),
							 sinsp_logger::SEV_DEBUG);
	if(m_components.empty())
	{
		if(events_only)
		{
			m_components.insert({ k8s_component::K8S_EVENTS, "events"});
			return;
		}
		m_components.insert({ k8s_component::K8S_NODES,                  "nodes"                  });
		m_components.insert({ k8s_component::K8S_NAMESPACES,             "namespaces"             });
		m_components.insert({ k8s_component::K8S_PODS,                   "pods"                   });
		m_components.insert({ k8s_component::K8S_REPLICATIONCONTROLLERS, "replicationcontrollers" });
		m_components.insert({ k8s_component::K8S_SERVICES,               "services"               });
		if(event_filter)
		{
			m_components.insert({ k8s_component::K8S_EVENTS, "events"});
		}
		if(extensions)
		{
			for(const auto& ext : *extensions)
			{
				if(ext == "daemonsets")
				{
					m_components.insert({ k8s_component::K8S_DAEMONSETS,  "daemonsets"  });
				}
				else if(ext == "deployments")
				{
					m_components.insert({ k8s_component::K8S_DEPLOYMENTS, "deployments" });
				}
				else if(ext == "replicasets")
				{
					m_components.insert({ k8s_component::K8S_REPLICASETS, "replicasets" });
				}
			}
		}
	}
}

k8s::~k8s()
{
	stop_watch();
	cleanup();
}

void k8s::stop_watch()
{
#ifdef HAS_CAPTURE
	if(m_net)
	{
		m_net->stop_watching();
	}
#endif
}

void k8s::cleanup()
{
#ifdef HAS_CAPTURE
	delete m_net;
	m_net = nullptr;
#endif
}

void k8s::check_components()
{
#ifdef HAS_CAPTURE
	if(m_net)
	{
		for (auto it = m_components.cbegin(); it != m_components.cend();)
		{
			if(m_net->has_handler(*it))
			{
				k8s_net::handler_ptr_t handler = k8s_net::get_handler(m_net->handlers(), *it);
				if(handler)
				{
					k8s_handler::api_error_ptr handler_error = handler->error();
					// HTTP error > 400 means non-existing, forbidden, etc.
					if(handler_error && handler_error->code() >= 400)
					{
						std::string handler_name = handler->name();
						if(!k8s_component::is_critical(handler_name))
						{
							g_logger.log("K8s: removing " + handler_name + " due to HTTP error " +
										 std::to_string(handler_error->code()) +
										 ", reason: " + handler_error->reason() +
										 ", message: " + handler_error->message(),
										 sinsp_logger::SEV_WARNING);
							m_components.erase(it++);
							continue;
						}
						else
						{
							throw sinsp_exception(handler_error->to_string());
						}
					}
				}
			}
			else
			{
				if(it->first != k8s_component::K8S_EVENTS)
				{
					m_net->add_handler(*it);
				}
				else if(m_event_filter) // events only if filter is enabled
				{
					m_net->add_handler(*it);
				}
			}
			++it;
		}
	}
	else
	{
		throw sinsp_exception("K8s net object is null.");
	}
#endif
}

const k8s_state_t& k8s::get_state()
{
	return m_state;
}

void k8s::watch()
{
#ifdef HAS_CAPTURE
	if(m_net)
	{
		check_components();
		m_net->watch();
	}
#endif
}

void k8s::simulate_watch_event(const std::string& json, int version)
{
	Json::Value root;
	Json::Reader reader;
	k8s_component::type component_type = k8s_component::K8S_COMPONENT_COUNT;
	if(reader.parse(json, root, false))
	{
		const Json::Value& kind = root["kind"];
		if(!kind.isNull() && kind.isString())
		{
			std::string type = kind.asString();
			if(type == "Namespace")                  { component_type = k8s_component::K8S_NAMESPACES;             }
			else if(type == "Node")                  { component_type = k8s_component::K8S_NODES;                  }
			else if(type == "Pod")                   { component_type = k8s_component::K8S_PODS;                   }
			else if(type == "ReplicationController") { component_type = k8s_component::K8S_REPLICATIONCONTROLLERS; }
			else if(type == "ReplicaSet")            { component_type = k8s_component::K8S_REPLICASETS;            }
			else if(type == "Service")               { component_type = k8s_component::K8S_SERVICES;               }
			else if(type == "DaemonSet")             { component_type = k8s_component::K8S_DAEMONSETS;             }
			else if(type == "Deployment")            { component_type = k8s_component::K8S_DEPLOYMENTS;            }
			else if(type == "EventList")             { component_type = k8s_component::K8S_EVENTS;                 }
			else
			{
				g_logger.log("Unrecognized component type: " + type, sinsp_logger::SEV_ERROR);
				return;
			}
		}
		else
		{
			g_logger.log("Component type not found in JSON", sinsp_logger::SEV_ERROR);
			return;
		}
	}
	else
	{
		g_logger.log("Error parsing JSON", sinsp_logger::SEV_ERROR);
		return;
	}

	if(m_state.get_capture_version() == k8s_state_t::CAPTURE_VERSION_NONE)
	{
		m_state.set_capture_version(version);
	}
	static bool version_logged = false;
	if(!version_logged)
	{
		g_logger.log("K8s capture version: " + std::to_string(version), sinsp_logger::SEV_DEBUG);
		version_logged = true;
	}
	switch(version)
	{
	case k8s_state_t::CAPTURE_VERSION_1: // old capture format
		if(component_type < k8s_component::K8S_COMPONENT_COUNT)
		{
			if(m_dispatch_map.find(component_type) == m_dispatch_map.end())
			{
				m_dispatch_map[component_type] =
					std::unique_ptr<k8s_dispatcher>(new k8s_dispatcher(component_type, m_state));
			}
			m_dispatch_map[component_type]->extract_data(root, false);
		}
		else
		{
			throw sinsp_exception(std::string("K8s capture: unknown component type (") +
							  std::to_string(component_type) + ")");
		}
		break;
	case k8s_state_t::CAPTURE_VERSION_2:
		if(component_type < k8s_component::K8S_COMPONENT_COUNT)
		{
			if(m_handler_map.find(component_type) == m_handler_map.end())
			{
				m_handler_map[component_type] = k8s_net::make_handler(m_state, component_type, false);
			}
			if(m_handler_map[component_type])
			{
				m_handler_map[component_type]->handle_json(std::move(root));
			}
			else
			{
				throw sinsp_exception(std::string("K8s capture replay: error creating ") +
									  k8s_component::get_name(component_type) +
									  " handler");
			}
		}
		else
		{
			throw sinsp_exception(std::string("K8s capture: unknown component type (") +
							  std::to_string(component_type) + ")");
		}
		break;
	default:
		throw sinsp_exception(std::string("K8s capture: invalid capture version (") +
							  std::to_string(version) + ")");
	}
}

std::size_t k8s::count(k8s_component::type component) const
{
	switch (component)
	{
	case k8s_component::K8S_NODES:
		return m_state.get_nodes().size();

	case k8s_component::K8S_NAMESPACES:
		return m_state.get_namespaces().size();

	case k8s_component::K8S_PODS:
		return m_state.get_pods().size();

	case k8s_component::K8S_REPLICATIONCONTROLLERS:
		return m_state.get_rcs().size();

	case k8s_component::K8S_REPLICASETS:
		return m_state.get_rss().size();

	case k8s_component::K8S_SERVICES:
		return m_state.get_services().size();

	case k8s_component::K8S_DAEMONSETS:
		return m_state.get_daemonsets().size();

	case k8s_component::K8S_DEPLOYMENTS:
		return m_state.get_deployments().size();

	case k8s_component::K8S_EVENTS:
		return m_state.get_events().size();

	case k8s_component::K8S_COMPONENT_COUNT:
	default:
		break;
	}

	std::ostringstream os;
	os << "Unknown component " << static_cast<int>(component);
	throw sinsp_exception(os.str());
}
#endif // CYGWING_AGENT
