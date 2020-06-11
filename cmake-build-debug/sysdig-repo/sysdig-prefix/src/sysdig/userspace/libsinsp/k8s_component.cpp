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
// k8s_component.cpp
//

#include "k8s_component.h"
#include "k8s_state.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "user_event.h"
#include <sstream>
#include <iostream>

//
// container
//

k8s_container::k8s_container()
{
}

k8s_container::k8s_container(const std::string& name, const port_list& ports): m_name(name),
		m_ports(ports)
{
}

k8s_container::k8s_container(const k8s_container& other): m_name(other.m_name),
	m_ports(other.m_ports)
{
}

k8s_container::k8s_container(k8s_container&& other): m_name(std::move(other.m_name)),
	m_ports(std::move(other.m_ports))
{
}

k8s_container& k8s_container::operator=(const k8s_container& other)
{
	m_name = other.m_name;
	m_ports = other.m_ports;
	return *this;
}

bool k8s_container::has_port(const std::string& port_name) const
{
	for(const auto& port : m_ports)
	{
		if (port.get_name() == port_name)
		{
			return true;
		}
	}
	return false;
}

const k8s_container::port* k8s_container::get_port(const std::string& port_name) const
{
	for(const auto& port : m_ports)
	{
		if (port.get_name() == port_name)
		{
			return &port;
		}
	}
	return 0;
}

//
// component
//

const k8s_component::type_map k8s_component::list =
{
	{ k8s_component::K8S_NODES,                  "nodes"                  },
	{ k8s_component::K8S_NAMESPACES,             "namespaces"             },
	{ k8s_component::K8S_PODS,                   "pods"                   },
	{ k8s_component::K8S_REPLICATIONCONTROLLERS, "replicationcontrollers" },
	{ k8s_component::K8S_REPLICASETS,            "replicasets"            },
	{ k8s_component::K8S_SERVICES,               "services"               },
	{ k8s_component::K8S_DAEMONSETS,             "daemonsets"             },
	{ k8s_component::K8S_DEPLOYMENTS,            "deployments"            },
	{ k8s_component::K8S_EVENTS,                 "events"                 }
};

k8s_component::k8s_component(type comp_type, const std::string& name, const std::string& uid, const std::string& ns) :
	m_type(comp_type), m_name(name), m_uid(uid), m_ns(ns)
{
}

k8s_component::~k8s_component()
{
}

k8s_pair_list k8s_component::extract_object(const Json::Value& object, const std::string& name)
{
	k8s_pair_list entry_list;
	if(!object.isNull())
	{
		const Json::Value& entries = object[name];
		if(!entries.isNull())
		{
			Json::Value::Members members = entries.getMemberNames();
			for (auto& member : members)
			{
				const Json::Value& val = entries[member];
				if(!val.isNull() && val.isString())
				{
					entry_list.emplace_back(k8s_pair_t(member, val.asString()));
				}
			}
		}
	}
	return entry_list;
}

std::string k8s_component::get_name_u(type t)
{
	switch (t)
	{
	case K8S_NAMESPACES:
		return "NAMESPACE";
	case K8S_NODES:
		return "NODE";
	case K8S_PODS:
		return "POD";
	case K8S_REPLICATIONCONTROLLERS:
		return "REPLICATIONCONTROLLER";
	case K8S_REPLICASETS:
		return "REPLICASET";
	case K8S_SERVICES:
		return "SERVICE";
	case K8S_DAEMONSETS:
		return "DAEMONSET";
	case K8S_DEPLOYMENTS:
		return "DEPLOYMENT";
	case K8S_EVENTS:
		return "EVENT";
	case K8S_COMPONENT_COUNT:
	default:
		break;
	}

	std::ostringstream os;
	os << "Unknown component type " << static_cast<int>(t);
	throw sinsp_exception(os.str().c_str());
}

std::string k8s_component::get_name(type t)
{
	switch (t)
	{
	case K8S_NAMESPACES:
		return "namespaces";
	case K8S_NODES:
		return "nodes";
	case K8S_PODS:
		return "pods";
	case K8S_REPLICATIONCONTROLLERS:
		return "replicationcontrollers";
	case K8S_REPLICASETS:
		return "replicasets";
	case K8S_SERVICES:
		return "services";
	case K8S_DAEMONSETS:
		return "daemonsets";
	case K8S_DEPLOYMENTS:
		return "deployments";
	case K8S_EVENTS:
		return "events";
	case K8S_COMPONENT_COUNT:
	default:
		break;
	}

	std::ostringstream os;
	os << "Unknown component type " << static_cast<int>(t);
	throw sinsp_exception(os.str().c_str());
}

k8s_component::type k8s_component::get_type(const std::string& name)
{
	if(name == "namespaces")
	{
		return K8S_NAMESPACES;
	}
	else if(name == "nodes")
	{
		return K8S_NODES;
	}
	else if(name == "pods")
	{
		return K8S_PODS;
	}
	else if(name == "replicationcontrollers")
	{
		return K8S_REPLICATIONCONTROLLERS;
	}
	else if(name == "replicasets")
	{
		return K8S_REPLICASETS;
	}
	else if(name == "services")
	{
		return K8S_SERVICES;
	}
	else if(name == "daemonsets")
	{
		return K8S_DAEMONSETS;
	}
	else if(name == "deployments")
	{
		return K8S_DEPLOYMENTS;
	}
	else if(name == "events")
	{
		return K8S_EVENTS;
	}

	std::ostringstream os;
	os << "K8s: Unknown component name " << name;
	throw sinsp_exception(os.str().c_str());
}

std::string k8s_component::get_selector(type t)
{
	switch (t)
	{
	case K8S_PODS:
		return "?fieldSelector=status.phase%3DRunning";
	default:
		break;
	}
	return "";
}

std::string k8s_component::get_selector(const component_pair& p)
{
	return get_selector(p.first);
}

std::string k8s_component::get_selector(const std::string& name)
{
	return get_selector(get_type(name));
}

bool k8s_component::is_critical(type t)
{
	switch (t)
	{
		case K8S_NODES:
		case K8S_NAMESPACES:
		case K8S_PODS:
		case K8S_REPLICATIONCONTROLLERS:
		case K8S_SERVICES:
			return true;
		case K8S_EVENTS:
		case K8S_REPLICASETS:
		case K8S_DAEMONSETS:
		case K8S_DEPLOYMENTS:
		default:
			break;
	}
	return false;
}

bool k8s_component::is_critical(const component_pair& p)
{
	return is_critical(p.first);
}

bool k8s_component::is_critical(const std::string& name)
{
	return is_critical(get_type(name));
}

std::string k8s_component::get_api(type t, ext_list_ptr_t extensions)
{
	switch (t)
	{
	case K8S_NAMESPACES:
	case K8S_NODES:
	case K8S_PODS:
	case K8S_REPLICATIONCONTROLLERS:
	case K8S_SERVICES:
	case K8S_EVENTS:
		return "/api/v1/";
	case K8S_REPLICASETS:
	case K8S_DAEMONSETS:
	case K8S_DEPLOYMENTS:
		if(extensions && extensions->size())
		{
			return "/apis/extensions/v1beta1/";
		}
		else
		{
			return "";
		}
	case K8S_COMPONENT_COUNT:
	default:
		break;
	}

	std::ostringstream os;
	os << "K8s: Unknown component type " << static_cast<int>(t);
	throw sinsp_exception(os.str().c_str());
}

std::string k8s_component::get_api(const component_pair& p, ext_list_ptr_t extensions)
{
	return get_api(p.first, extensions);
}

std::string k8s_component::get_api(const std::string& name, ext_list_ptr_t extensions)
{
	return get_api(get_type(name), extensions);
}

k8s_pair_t* k8s_component::get_label(const k8s_pair_t& label)
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

void k8s_component::add_labels(k8s_pair_list&& labels)
{
	for (auto& label : labels)
	{
		if(!get_label(label))
		{
			emplace_label(std::move(label));
		}
	}
}

k8s_pair_t* k8s_component::get_selector(const k8s_pair_t& selector)
{
	for (auto& sel : m_selectors)
	{
		if((sel.first == selector.first) && (sel.second == selector.second))
		{
			return &sel;
		}
	}
	return 0;
}

void k8s_component::add_selectors(k8s_pair_list&& selectors)
{
	for (auto& selector : selectors)
	{
		if(!get_selector(selector))
		{
			emplace_selector(std::move(selector));
		}
	}
}

// TODO: proper selection process is more complicated, see “Labels and Selectors” at
// http://kubernetes.io/v1.0/docs/user-guide/labels.html
bool k8s_component::selector_in_labels(const k8s_pair_t& selector, const k8s_pair_list& labels) const
{
	if(!labels.size()) { return false; }
	for(const auto& label : labels)
	{
		if(label.first == selector.first && label.second == selector.second)
		{
			return true;
		}
	}
	return false;
}

bool k8s_component::selectors_in_labels(const k8s_pair_list& labels) const
{
	const k8s_pair_list& selectors = get_selectors();
	if(!labels.size() || !selectors.size()) { return false; }
	for(const auto& selector : selectors)
	{
		if(!selector_in_labels(selector, labels))
		{
			return false;
		}
	}
	return true;
}

//
// namespace
//
k8s_ns_t::k8s_ns_t(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(COMPONENT_TYPE, name, uid, ns)
{
}


//
// node
//

k8s_node_t::k8s_node_t(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(COMPONENT_TYPE, name, uid, ns)
{
}

k8s_node_t::host_ip_list k8s_node_t::extract_addresses(const Json::Value& status)
{
	host_ip_list address_list;
	if(!status.isNull())
	{
		const Json::Value& addresses = status["addresses"];
		if(!addresses.isNull() && addresses.isArray())
		{
			for (auto& address : addresses)
			{
				if(address.isObject())
				{
					Json::Value::Members addr_names_list = address.getMemberNames();
					for (auto& entry : addr_names_list)
					{
						if(entry == "address")
						{
							const Json::Value& ip = address[entry];
							if(!ip.isNull())
							{
								address_list.emplace(ip.asString());
							}
						}
					}
				}
			}
		}
	}
	return address_list;
}


//
// pod
//

k8s_pod_t::k8s_pod_t(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(COMPONENT_TYPE, name, uid, ns)
{
}

//
// replicas
//

k8s_replicas_t::k8s_replicas_t(int spec_replicas, int stat_replicas):
	m_spec_replicas(spec_replicas),
	m_stat_replicas(stat_replicas)
{
}

int k8s_replicas_t::get_count(const Json::Value& item, const std::string& replica_name)
{
	if(!item.isNull())
	{
		const Json::Value& replicas = item[replica_name];
		if(!replicas.isNull() && replicas.isConvertibleTo(Json::intValue))
		{
			return replicas.asInt();
		}
	}

	if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
	{
		g_logger.log("K8s: Can not find " + replica_name + " in \n" + Json::FastWriter().write(item),
					 sinsp_logger::SEV_DEBUG);

		std::string name;
		const Json::Value& tpl = item["template"];
		if(!tpl.isNull())
		{
			const Json::Value& md = tpl["metadata"];
			if(!md.isNull())
			{
				const Json::Value& lbl = md["labels"];
				if(!lbl.isNull())
				{
					const Json::Value& n = lbl["name"];
					if(!n.isNull() && n.isString())
					{
						name = n.asString();
					}
					else
					{
						const Json::Value& n = lbl["app"];
						if(!n.isNull() && n.isString())
						{
							name = n.asString();
						}
					}
				}
			}
		}

		g_logger.log("K8s: Can not determine number of replicas" +
					 (name.empty() ? std::string() : std::string(" for ").append(name)),
					 sinsp_logger::SEV_DEBUG);
	}

	return k8s_replicas_t::UNKNOWN_REPLICAS;
}

void k8s_replicas_t::set_replicas(k8s_replicas_t& replicas, const Json::Value& item)
{
	int replica_count = k8s_replicas_t::get_count(item["spec"], "replicas");
	if(replica_count != k8s_replicas_t::UNKNOWN_REPLICAS)
	{
		replicas.set_spec_replicas(replica_count);
	}
	replica_count = k8s_replicas_t::get_count(item["status"], "replicas");
	if(replica_count != k8s_replicas_t::UNKNOWN_REPLICAS)
	{
		replicas.set_stat_replicas(replica_count);
	}
	else
	{
		int unavailable_replicas = k8s_replicas_t::get_count(item["status"], "unavailableReplicas");
		int spec_replicas = replicas.get_spec_replicas();
		if(spec_replicas != k8s_replicas_t::UNKNOWN_REPLICAS && unavailable_replicas < spec_replicas)
		{
			replicas.set_stat_replicas(spec_replicas - unavailable_replicas);
		}
	}
}

//
// replication controller
//

k8s_rc_t::k8s_rc_t(const std::string& name, const std::string& uid, const std::string& ns, k8s_component::type type) :
	k8s_component(type, name, uid, ns)
{
}

std::vector<const k8s_pod_t*> k8s_rc_t::get_selected_pods(const std::vector<k8s_pod_t>& pods) const
{
	std::vector<const k8s_pod_t*> pod_vec;
	for(const auto& pod : pods)
	{
		if(selectors_in_labels(pod.get_labels()) && get_namespace() == pod.get_namespace())
		{
			pod_vec.push_back(&pod);
		}
	}
	return pod_vec;
}

void k8s_rc_t::set_replicas(int spec, int stat)
{
	set_spec_replicas(spec);
	set_stat_replicas(stat);
}

//
// replica set
//
k8s_rs_t::k8s_rs_t(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_rc_t(name, uid, ns, COMPONENT_TYPE)
{
}


//
// service
//

k8s_service_t::k8s_service_t(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(COMPONENT_TYPE, name, uid, ns)
{
}

std::vector<const k8s_pod_t*> k8s_service_t::get_selected_pods(const std::vector<k8s_pod_t>& pods) const
{
	std::vector<const k8s_pod_t*> pod_vec;
	for(const auto& pod : pods)
	{
		if (selectors_in_labels(pod.get_labels()) && get_namespace() == pod.get_namespace())
		{
			pod_vec.push_back(&pod);
		}
	}
	return pod_vec;
}


//
// daemon set
//

k8s_daemonset_t::k8s_daemonset_t(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(COMPONENT_TYPE, name, uid, ns)
{
}


//
// deployment
//

k8s_deployment_t::k8s_deployment_t(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(COMPONENT_TYPE, name, uid, ns)
{
}

std::vector<const k8s_pod_t*> k8s_deployment_t::get_selected_pods(const std::vector<k8s_pod_t>& pods) const
{
	std::vector<const k8s_pod_t*> pod_vec;
	for(const auto& pod : pods)
	{
		if(selectors_in_labels(pod.get_labels()) && get_namespace() == pod.get_namespace())
		{
			pod_vec.push_back(&pod);
		}
	}
	return pod_vec;
}

//
// event
//

k8s_event_t::k8s_event_t(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(COMPONENT_TYPE, name, uid, ns),
	m_name_translation
	{
		//
		// Event translations, based on:
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/container/event.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/controller_utils.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/node/nodecontroller.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/kubelet.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/daemon/controller.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/deployment/deployment_controller.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/deployment/util/deployment_util.go
		//

		//
		// Node
		//

		// Node Controller
		{ "TerminatedAllPods",     "Terminated All Pods"},
		{ "RegisteredNode",        "Node Registered"},
		{ "RemovingNode",          "Removing Node"},
		{ "DeletingNode",          "Deleting Node"},
		{ "DeletingAllPods",       "Deleting All Pods"},
		{ "TerminatingEvictedPod", "Terminating Evicted Pod" },

		// Kubelet
		{ "NodeReady",               "Node Ready"                 },
		{ "NodeNotReady",            "Node not Ready"             },
		{ "NodeSchedulable",         "Node is Schedulable"        },
		{ "NodeNotSchedulable",      "Node is not Schedulable"    },
		{ "CIDRNotAvailable",        "CIDR not Available"         },
		{ "CIDRAssignmentFailed",    "CIDR Assignment Failed"     },
		{ "Starting",                "Starting Kubelet"           },
		{ "KubeletSetupFailed",      "Kubelet Setup Failed"       },
		{ "FailedMount",             "Volume Mount Failed"        },
		{ "NodeSelectorMismatching", "Node Selector Mismatch"     },
		{ "InsufficientFreeCPU",     "Insufficient Free CPU"      },
		{ "InsufficientFreeMemory",  "Insufficient Free Memory"   },
		{ "OutOfDisk",               "Out of Disk"                },
		{ "HostNetworkNotSupported", "Host Network not Supported" },
		{ "NilShaper",               "Undefined Shaper"           },
		{ "Rebooted",                "Node Rebooted"              },
		{ "NodeHasSufficientDisk",   "Node Has Sufficient Disk"   },
		{ "NodeOutOfDisk",           "Node Out of Disk Space"     },

		// Image manager
		{ "InvalidDiskCapacity", "Invalid Disk Capacity"  },
		{ "FreeDiskSpaceFailed", "Free Disk Space Failed" },

		//
		// Pod
		//

		// Image
		{ "Pulling",           "Pulling Image"                                },
		{ "Pulled",            "Image Pulled"                                 },
		{ "Failed",            "Container Image Pull, Create or Start Failed" },
		{ "InspectFailed",     "Image Inspect Failed"                         },
		{ "ErrImageNeverPull", "Image NeverPull Policy Error"                 },
		{ "BackOff",           "Back Off Container Start or Image Pull"       },

		//{ "OutOfDisk" ,"Out of Disk" }, duplicate

		// Container
		{ "Created", "Container Created"                },
		{ "Started", "Container Started"                },
		//{ "Failed",  "Container Create or Start Failed" }, duplicate
		{ "Killing", "Killing Container"                },

		//{ "BackOff", "Backoff Start Container" }, duplicate

		// Probe
		{ "Unhealthy", "Container Unhealthy" },

		// Pod worker
		{ "FailedSync", "Pod Sync Failed" },

		// Config
		{ "FailedValidation", "Failed Configuration Validation" },
		{ "HostPortConflict", "Host/Port Conflict"              },

		//
		// Replication Controller
		//
		{ "SuccessfulCreate",  "Pod Created"      },
		{ "FailedCreate",      "Pod Create Failed"},
		{ "SuccessfulDelete",  "Pod Deleted"      },
		{ "FailedDelete",      "Pod Delete Failed"},

		//
		// Replica Set
		//
		// { "SuccessfulCreate",  "Pod Created"      }, duplicate
		// { "FailedCreate",      "Pod Create Failed"}, duplicate
		// { "SuccessfulDelete",  "Pod Deleted"      }, duplicate
		// { "FailedDelete",      "Pod Delete Failed"}  duplicate

		//
		// Deployment
		//
		{ "SelectingAll",                        "Selecting All Pods"       },
		{ "ScalingReplicaSet",                   "Scaling Replica Set"      },
		{ "DeploymentRollbackRevisionNotFound",  "No revision to roll back" },
		{ "DeploymentRollbackTemplateUnchanged", "Skipping Rollback"        },
		{ "DeploymentRollback",                  "Rollback Done"            }

		//
		// Daemon Set
		//
		// { "SelectingAll", "Selecting All Pods" } duplicate
	}
{
}

void k8s_event_t::post_process(k8s_state_t& state)
{
	for(auto it = m_postponed_events.cbegin(); it != m_postponed_events.end();)
	{
		g_logger.log("K8s event: " + std::to_string(m_postponed_events.size()) + " postponed events. "
					 "post-processing event [" + it->first + "] ...", sinsp_logger::SEV_TRACE);
		m_force_delete = false;
		bool updated = update(it->second, state);
		if(updated || m_force_delete)
		{
			g_logger.log("K8s event: event [" + it->first +
						 "] post-processed.", sinsp_logger::SEV_TRACE);
			m_postponed_events.erase(it++);
		}
		else
		{
			g_logger.log("K8s event: event [" + it->first + "] not post-processed. There's " +
						 std::to_string(m_postponed_events.size()) +
						 " postponed events pending.", sinsp_logger::SEV_TRACE);
			++it;
		}
	}
}

bool k8s_event_t::update(const Json::Value& item, k8s_state_t& state)
{
#ifndef _WIN32
	time_t      epoch_time_evt_s = 0;
	time_t      epoch_time_now_s = get_epoch_utc_seconds_now();
	std::string event_name;
	std::string description;
	severity_t  severity = user_event_logger::SEV_EVT_INFORMATION;
	event_scope scope;
	tag_map_t   tags;

	const Json::Value& obj = item["involvedObject"];
	if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
	{
		g_logger.log("K8s EVENT: \n" + json_as_string(item), sinsp_logger::SEV_TRACE);
	}
	if(!obj.isNull())
	{
		std::string sev = get_json_string(item, "type");
		// currently, only "Normal" and "Warning"
		severity = user_event_logger::SEV_EVT_INFORMATION;
		if(sev == "Warning") { severity = user_event_logger::SEV_EVT_WARNING; }
		if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
		{
			g_logger.log("K8s EVENT:"
						"\nnamespace = " + get_json_string(obj, "namespace") +
						"\nname = " + get_json_string(obj, "name") +
						"\nuid = " + get_json_string(obj, "uid") +
						"\ntype = " + get_json_string(obj, "kind") +
						"\nseverity = " + get_json_string(item, "type") + " (" + std::to_string(severity) + ')', sinsp_logger::SEV_TRACE);
		}
	}
	else
	{
		g_logger.log("K8s event: cannot get involved object (null)", sinsp_logger::SEV_ERROR);
		m_force_delete = true;
		return false;
	}

	std::string ts = get_json_string(item , "lastTimestamp");
	if(!ts.empty())
	{
		if((epoch_time_evt_s = get_epoch_utc_seconds(ts)) == (time_t) -1)
		{
			g_logger.log("K8s event: cannot convert [" + ts + "] to epoch timestamp", sinsp_logger::SEV_ERROR);
		}
		g_logger.log("K8s EVENT update: time:" + std::to_string(epoch_time_evt_s), sinsp_logger::SEV_DEBUG);
	}
	else
	{
		g_logger.log("K8s event: cannot convert time (null, empty or not string)", sinsp_logger::SEV_ERROR);
	}
	event_name = get_json_string(item , "reason");
	const auto& translation = m_name_translation.find(event_name);
	if(translation != m_name_translation.end())
	{
		event_name = translation->second;
	}
	description = get_json_string(item, "message");
	g_logger.log("K8s EVENT message:" + description, sinsp_logger::SEV_DEBUG);

	// Although it's easier and more efficient to obtain the involved object data from
	// the event itself, there is a downside - event may not carry the data in the
	// same format as reported in metadata protobuf (generated from k8s state);
	// an example is IP address vs. DNS name for node, there may be other cases.
	// For that reason, we try to obtain info about involved object from state; if object is
	// not found in state (due to undefined arrival order of event and metadata messages),
	// we get scope data from the event itself.
	std::string component_uid = get_json_string(obj, "uid");
	g_logger.log("K8s event UID:" + component_uid, sinsp_logger::SEV_TRACE);
	if(!component_uid.empty())
	{
		g_logger.log("K8s event: seconds since event occurred:" + std::to_string(epoch_time_now_s - epoch_time_evt_s),
					 sinsp_logger::SEV_TRACE);
		std::string t;
		const k8s_component* comp = state.get_component(component_uid, &t);
		if(comp && !t.empty())
		{
			const std::string& node_name = comp->get_node_name();
			if(!node_name.empty())
			{
				scope.add("kubernetes.node.name", node_name);
			}
			const std::string& ns = comp->get_namespace();
			if(!ns.empty())
			{
				scope.add("kubernetes.namespace.name", ns);
			}
			const std::string& comp_name = comp->get_name();
			if(!comp_name.empty())
			{
				scope.add(std::string("kubernetes.").append(t).append(".name"), comp_name);
			}
			/* no labels for now
			for(const auto& label : comp->get_labels())
			{
				tags[label.first] = label.second;
				//g_logger.log("EVENT label: [" + label.first + ':' + label.second + ']', sinsp_logger::SEV_DEBUG);
				if(event_scope::check(label.second))
				{
					scope.append(" and kubernetes.").append(t).append(".label.").append(label.first).append(1, '=').append(label.second);
				}
				else
				{
					g_logger.log("K8s invalid scope entry: [" + label.second + ']', sinsp_logger::SEV_WARNING);
				}
			}*/
		}
		else
		{
			g_logger.log("K8s event: cannot obtain component (component with UID [" + component_uid +
						 "] not found), trying to build scope directly from event ...", sinsp_logger::SEV_TRACE);
			make_scope(obj, scope);
		}
	}
	else
	{
		g_logger.log("K8s event: cannot obtain component UID, trying to build scope directly from event ...",
					 sinsp_logger::SEV_TRACE);
		make_scope(obj, scope);
	}

	tags["source"] = "kubernetes";

	auto evt = sinsp_user_event(epoch_time_evt_s,
				    std::move(event_name),
				    std::move(description),
				    std::move(scope.get_ref()),
				    std::move(tags),
				    severity);

	user_event_logger::log(evt, severity);

	// TODO: sysdig capture?
#endif // _WIN32

	return true;
}

void k8s_event_t::make_scope_impl(const Json::Value& obj, std::string comp, event_scope& scope, bool ns)
{
	if(ns)
	{
		const std::string& ns_name = get_json_string(obj, "namespace");
		if(!ns_name.empty())
		{
			scope.add("kubernetes.namespace.name", ns_name);
		}
	}
	if(comp.length() && ci_compare::is_equal(get_json_string(obj, "kind"), comp))
	{
		const std::string& comp_name = get_json_string(obj, "name");
		if(!comp_name.empty())
		{
			comp[0] = tolower(comp[0]);
			scope.add(std::string("kubernetes.").append(comp).append(".name"), comp_name);
		}
		if(comp_name.empty())
		{
			g_logger.log("K8s " + comp + " event detected but " + comp + " name could not be determined. Scope will be empty.", sinsp_logger::SEV_WARNING);
		}
	}
	else
	{
		g_logger.log("K8s event detected but component name was empty. Scope will be empty.", sinsp_logger::SEV_WARNING);
	}
}

void k8s_event_t::make_scope(const Json::Value& obj, event_scope& scope)
{
	if(ci_compare::is_equal(get_json_string(obj, "kind"), "Pod"))
	{
		make_scope_impl(obj, "Pod", scope);
	}
	else if(ci_compare::is_equal(get_json_string(obj, "kind"), "ReplicationController"))
	{
		make_scope_impl(obj, "ReplicationController", scope);
	}
	else if(ci_compare::is_equal(get_json_string(obj, "kind"), "Node"))
	{
		make_scope_impl(obj, "Node", scope, false);
	}
	else if(ci_compare::is_equal(get_json_string(obj, "kind"), "ReplicaSet"))
	{
		make_scope_impl(obj, "ReplicaSet", scope);
	}
	else if(ci_compare::is_equal(get_json_string(obj, "kind"), "Deployment"))
	{
		make_scope_impl(obj, "Deployment", scope);
	}
	else if(ci_compare::is_equal(get_json_string(obj, "kind"), "DaemonSet"))
	{
		make_scope_impl(obj, "DaemonSet", scope);
	}
}
