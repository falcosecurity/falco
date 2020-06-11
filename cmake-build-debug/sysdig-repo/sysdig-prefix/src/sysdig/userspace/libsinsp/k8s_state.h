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
// k8s_state.h
//
// kubernetes state abstraction
//

#pragma once

#include "k8s_component.h"
#include "json/json.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <vector>
#include <map>
#include <unordered_map>

//
// state
//

class k8s_state_t
{
public:
	typedef std::unordered_map<std::string, const k8s_ns_t*>           namespace_map;
	typedef std::unordered_map<std::string, const k8s_pod_t*>          container_pod_map;
	typedef std::unordered_multimap<std::string, const k8s_service_t*> pod_service_map;
	typedef std::unordered_map<std::string, const k8s_rc_t*>           pod_rc_map;
	typedef std::unordered_map<std::string, const k8s_rs_t*>           pod_rs_map;
	typedef std::unordered_multimap<std::string, const k8s_deployment_t*> pod_deployment_map;

	static const int CAPTURE_VERSION_NONE = -1;
	static const int CAPTURE_VERSION_1 = 1;
	static const int CAPTURE_VERSION_2 = 2;

	k8s_state_t(bool is_captured = false, int capture_version = CAPTURE_VERSION_2);

	//
	// namespaces
	//

	const k8s_namespaces& get_namespaces() const;
	k8s_namespaces& get_namespaces();
	void push_namespace(const k8s_ns_t& ns);
	void emplace_namespace(k8s_ns_t&& ns);

	//
	// nodes
	//

	const k8s_nodes& get_nodes() const;
	k8s_nodes& get_nodes();
	k8s_node_t* get_node(const std::string& uid);
	void push_node(const k8s_node_t& node);
	void emplace_node(k8s_node_t&& node);

	//
	// pods
	//

	const k8s_pods& get_pods() const;
	k8s_pods& get_pods();
	void push_pod(const k8s_pod_t& pod);
	void emplace_pod(k8s_pod_t&& pod);
	void update_pod(k8s_pod_t& pod, const Json::Value& item);
	bool has_pod(k8s_pod_t& pod);
	const k8s_pod_t::container_id_list& get_pod_container_ids(k8s_pod_t& pod);

	//
	// replication controllers
	//

	const k8s_controllers& get_rcs() const;
	k8s_controllers& get_rcs();
	void push_rc(const k8s_rc_t& rc);
	void emplace_rc(k8s_rc_t&& rc);

	//
	// replica sets
	//

	const k8s_replicasets& get_rss() const;
	k8s_replicasets& get_rss();
	void push_rs(const k8s_rs_t& rs);
	void emplace_rs(k8s_rs_t&& rs);

	//
	// services
	//

	const k8s_services& get_services() const;
	k8s_services& get_services();
	void push_service(const k8s_service_t& service);
	void emplace_service(k8s_service_t&& service);

	//
	// daemonsets
	//

	const k8s_daemonsets& get_daemonsets() const;
	k8s_daemonsets& get_daemonsets();
	void push_daemonset(const k8s_daemonset_t& daemonset);
	void emplace_daemonset(k8s_daemonset_t&& daemonset);

	//
	// deployments
	//

	const k8s_deployments& get_deployments() const;
	k8s_deployments& get_deployments();
	void push_deployment(const k8s_deployment_t& deployment);
	void emplace_deployment(k8s_deployment_t&& deployment);

	//
	// events
	//

	const k8s_events& get_events() const;
	k8s_events& get_events();
	void clear_events();
	void push_event(const k8s_event_t& evt);
	void emplace_event(k8s_event_t&& evt);
	void update_event(k8s_event_t& evt, const Json::Value& item);

	//
	// general
	//

	void replace_items(k8s_component::type t, const std::string& name, const std::vector<k8s_pair_t>&& items);
	k8s_component& add_common_single_value(k8s_component::type component, const std::string& name, const std::string& uid, const std::string& ns);
	void set_last_pod_node_name(const std::string& name);
	void set_last_pod_host_ip(const std::string& host_ip);
	void set_last_pod_internal_ip(const std::string& internal_ip);
	void add_last_node_ip(std::string&& ip);
	void add_last_pod_container_id(std::string&& container_id);

	// Returns true if component exists, false otherwise.
	template <typename C>
	bool has(const C& components, const std::string& uid) const
	{
		for (auto& comp : components)
		{
			if(uid == comp.get_uid())
			{
				return true;
			}
		}
		return false;
	}

	bool has(const std::string& uid) const
	{
		return get_component(uid) != nullptr;
	}

	// Returns a pointer to existing component, if it exists.
	// If component does not exist, it returns null pointer.
	template <typename C, typename T>
	T* get_component(C& components, const std::string& uid)
	{
		for (auto& comp : components)
		{
			if(comp.get_uid() == uid)
			{
				return &comp;
			}
		}
		return 0;
	}

	template <typename C, typename T>
	const T* get_component(const C& components, const std::string& uid) const
	{
		for (const auto& comp : components)
		{
			if(comp.get_uid() == uid)
			{
				return &comp;
			}
		}
		return 0;
	}

	template <typename C, typename T>
	T& add_component(C& container, const std::string& name, const std::string& uid, const std::string& ns = "")
	{
		m_component_map[uid] = T::COMPONENT_TYPE;
		container.emplace_back(std::move(T(name, uid, ns)));
		return container.back();
	}

	// Returns the reference to existing component, if it exists.
	// If component does not exist, it emplaces it to the back of the
	// container and returns the reference of the added component.
	template <typename C, typename T>
	T& get_component(C& container, const std::string& name, const std::string& uid, const std::string& ns = "")
	{
		for (auto& comp : container)
		{
			if(comp.get_uid() == uid)
			{
				return comp;
			}
		}
		return add_component<C, T>(container, name, uid, ns);
	}

	template <typename C>
	bool delete_component(C& components, const std::string& uid)
	{
		for (typename C::iterator component = components.begin(),
			end = components.end();
			component != end;
			++component)
		{
			if(component->get_uid() == uid)
			{
				components.erase(component);
				m_component_map.erase(uid);
				return true;
			}
		}

		return false;
	}

	void clear(k8s_component::type type = k8s_component::K8S_COMPONENT_COUNT);

	//
	// cached lookup support
	//

	// any component by uid
	const k8s_component* get_component(const std::string& uid, std::string* t = 0) const;

#ifndef HAS_ANALYZER

	// pod by container;
	const k8s_pod_t* get_pod(const std::string& container) const
	{
		container_pod_map::const_iterator it = m_container_pods.find(container);
		if(it != m_container_pods.end())
		{
			return it->second;
		}
		return 0;
	}

	const namespace_map& get_namespace_map() const { return m_namespace_map; }
	const container_pod_map& get_container_pod_map() const { return m_container_pods; }
	const pod_service_map& get_pod_service_map() const { return m_pod_services; }
	const pod_rc_map& get_pod_rc_map() const { return m_pod_rcs; }
	const pod_rs_map& get_pod_rs_map() const { return m_pod_rss; }
	const pod_deployment_map& get_pod_deployment_map() const { return m_pod_deployments; }

#endif // HAS_ANALYZER

	void set_capture_version(int version);
	int get_capture_version() const;

#ifdef HAS_CAPTURE
	typedef std::deque<std::string> event_list_t;
	const event_list_t& get_capture_events() const { return m_capture_events; }
	void enqueue_capture_event(const Json::Value& item);
	std::string dequeue_capture_event();
#endif // HAS_CAPTURE

private:

	void update_cache(const k8s_component::type_map::key_type& component);
	static k8s_component::type component_from_json(const Json::Value& item);
	static Json::Value extract_capture_data(const Json::Value& item);

	template<typename C>
	const typename C::mapped_type* get_component(const C& map, const std::string& key)
	{
		typename C::const_iterator it = map.find(key);
		if(it != map.end())
		{
			return it->second;
		}
		return 0;
	}

	template<typename C>
	bool is_component_cached(const C& map, const std::string& key) const
	{
		return (map.find(key) != map.end());
	}

	template<typename C>
	bool is_component_cached(const C& map, const std::string& key, const typename C::mapped_type value) const
	{
		auto range = map.equal_range(key);
		for (auto& it = range.first; it != range.second; ++it)
		{
			if(it->first == key && it->second == value)
			{
				return true;
			}
		}
		return false;
	}

	void cache_pod(container_pod_map& map, const std::string& id, const k8s_pod_t* pod);

	template<typename C>
	void cache_component(C& map, const std::string& key, typename C::mapped_type component)
	{
		ASSERT(component);
		ASSERT(!component->get_name().empty());
		map.insert(typename C::value_type(key, component));
		return;
	}

	template<typename C>
	void uncache_component(C& map, const std::string& key)
	{
		typename C::iterator it = map.find(key);
		if(it != map.end())
		{
			map.erase(it);
		}
	}

#ifndef HAS_ANALYZER

	namespace_map& get_namespace_map() { return m_namespace_map; }
	container_pod_map& get_container_pod_map() { return m_container_pods; }
	pod_service_map& get_pod_service_map() { return m_pod_services; }
	pod_rc_map& get_pod_rc_map() { return m_pod_rcs; }
	pod_rs_map& get_pod_rs_map() { return m_pod_rss; }
	pod_deployment_map& get_pod_deployment_map() { return m_pod_deployments; }

#endif // HAS_ANALYZER

	static const std::string m_docker_prefix; // "docker://"
	static const std::string m_rkt_prefix; // "rkt://"
	static const std::string m_containerd_prefix; // "containerd://"
	static const std::string m_crio_prefix; // "cri-o://"
	static const unsigned    m_id_length; // portion of the ID to be cached (=12)

#ifndef HAS_ANALYZER

	namespace_map            m_namespace_map;
	container_pod_map        m_container_pods;
	pod_service_map          m_pod_services;
	pod_rc_map               m_pod_rcs;
	pod_rs_map               m_pod_rss;
	pod_deployment_map       m_pod_deployments;

#endif // HAS_ANALYZER

#ifdef HAS_CAPTURE
	event_list_t             m_capture_events;
#endif // HAS_CAPTURE

	typedef std::unordered_map<std::string, k8s_component::type> component_map_t;

	k8s_namespaces  m_namespaces;
	k8s_nodes       m_nodes;
	k8s_pods        m_pods;
	k8s_controllers m_controllers;
	k8s_replicasets m_replicasets;
	k8s_services    m_services;
	k8s_daemonsets  m_daemonsets;
	k8s_deployments m_deployments;
	k8s_events      m_events;
	// map for uid/type cache for all components
	// used by to quickly lookup any component by uid
	component_map_t m_component_map;
	bool            m_is_captured;
	int             m_capture_version = -1;

	friend class k8s_dispatcher;
	friend class k8s_handler;
	friend class k8s;
};

// namespaces
inline const k8s_namespaces& k8s_state_t::get_namespaces() const
{
	return m_namespaces;
}

inline k8s_namespaces& k8s_state_t::get_namespaces()
{
	return m_namespaces;
}

inline void k8s_state_t::push_namespace(const k8s_ns_t& ns)
{
	m_namespaces.push_back(ns);
}

inline void k8s_state_t::emplace_namespace(k8s_ns_t&& ns)
{
	m_namespaces.emplace_back(std::move(ns));
}

// nodes
inline const k8s_nodes& k8s_state_t::get_nodes() const
{
	return m_nodes;
}

inline k8s_nodes& k8s_state_t::get_nodes()
{
	return m_nodes;
}

inline void k8s_state_t::push_node(const k8s_node_t& node)
{
	m_nodes.push_back(node);
}

inline void k8s_state_t::emplace_node(k8s_node_t&& node)
{
	m_nodes.emplace_back(std::move(node));
}

// pods
inline const k8s_pods& k8s_state_t::get_pods() const
{
	return m_pods;
}

inline k8s_pods& k8s_state_t::get_pods()
{
	return m_pods;
}

inline void k8s_state_t::push_pod(const k8s_pod_t& pod)
{
	m_pods.push_back(pod);
}

inline void k8s_state_t::emplace_pod(k8s_pod_t&& pod)
{
	m_pods.emplace_back(std::move(pod));
}

inline const k8s_pod_t::container_id_list& k8s_state_t::get_pod_container_ids(k8s_pod_t& pod)
{
	return pod.get_container_ids();
}

// replication controllers
inline const k8s_controllers& k8s_state_t::get_rcs() const
{
	return m_controllers;
}

inline k8s_controllers& k8s_state_t::get_rcs()
{
	return m_controllers;
}

inline void k8s_state_t::push_rc(const k8s_rc_t& rc)
{
	m_controllers.push_back(rc);
}

inline void k8s_state_t::emplace_rc(k8s_rc_t&& rc)
{
	m_controllers.emplace_back(std::move(rc));
}

// replica sets
inline const k8s_replicasets& k8s_state_t::get_rss() const
{
	return m_replicasets;
}

inline k8s_replicasets& k8s_state_t::get_rss()
{
	return m_replicasets;
}

inline void k8s_state_t::push_rs(const k8s_rs_t& rs)
{
	m_replicasets.push_back(rs);
}

inline void k8s_state_t::emplace_rs(k8s_rs_t&& rs)
{
	m_replicasets.emplace_back(std::move(rs));
}

// services
inline const k8s_services& k8s_state_t::get_services() const
{
	return m_services;
}

inline k8s_services& k8s_state_t::get_services()
{
	return m_services;
}

inline void k8s_state_t::push_service(const k8s_service_t& service)
{
	m_services.push_back(service);
}

inline void k8s_state_t::emplace_service(k8s_service_t&& service)
{
	m_services.emplace_back(std::move(service));
}

// daemonsets
inline const k8s_daemonsets& k8s_state_t::get_daemonsets() const
{
	return m_daemonsets;
}

inline k8s_daemonsets& k8s_state_t::get_daemonsets()
{
	return m_daemonsets;
}

inline void k8s_state_t::push_daemonset(const k8s_daemonset_t& daemonset)
{
	m_daemonsets.push_back(daemonset);
}

inline void k8s_state_t::emplace_daemonset(k8s_daemonset_t&& daemonset)
{
	m_daemonsets.emplace_back(std::move(daemonset));
}

// deployments
inline const k8s_deployments& k8s_state_t::get_deployments() const
{
	return m_deployments;
}

inline k8s_deployments& k8s_state_t::get_deployments()
{
	return m_deployments;
}

inline void k8s_state_t::push_deployment(const k8s_deployment_t& deployment)
{
	m_deployments.push_back(deployment);
}

inline void k8s_state_t::emplace_deployment(k8s_deployment_t&& deployment)
{
	m_deployments.emplace_back(std::move(deployment));
}

// events
inline const k8s_events& k8s_state_t::get_events() const
{
	return m_events;
}

inline k8s_events& k8s_state_t::get_events()
{
	return m_events;
}

inline void k8s_state_t::clear_events()
{
	for(auto it = m_events.begin(); it != m_events.end();)
	{
		it->post_process((*this));
		if(!it->has_pending_events())
		{
			it = m_events.erase(it);
		}
		else
		{
			++it;
		}
	}
}

inline void k8s_state_t::push_event(const k8s_event_t& evt)
{
	m_events.push_back(evt);
}

inline void k8s_state_t::emplace_event(k8s_event_t&& evt)
{
	m_events.emplace_back(std::move(evt));
}

// general
inline void k8s_state_t::set_last_pod_node_name(const std::string& name)
{
	if(m_pods.size())
	{
		m_pods.back().set_node_name(name);
	}
}

inline void k8s_state_t::set_last_pod_host_ip(const std::string& host_ip)
{
	if(m_pods.size())
	{
		m_pods.back().set_host_ip(host_ip);
	}
}

inline void k8s_state_t::set_last_pod_internal_ip(const std::string& internal_ip)
{
	if(m_pods.size())
	{
		m_pods.back().set_internal_ip(internal_ip);
	}
}

inline void k8s_state_t::add_last_node_ip(std::string&& ip)
{
	if(m_nodes.size())
	{
		m_nodes.back().emplace_host_ip(std::move(ip));
	}
}

inline void k8s_state_t::add_last_pod_container_id(std::string&& container_id)
{
	if(m_pods.size())
	{
		m_pods.back().emplace_container_id(std::move(container_id));
	}
}

inline void k8s_state_t::set_capture_version(int version)
{
	if(version != CAPTURE_VERSION_NONE &&
	   version != CAPTURE_VERSION_1 &&
	   version != CAPTURE_VERSION_2)
	{
		throw sinsp_exception(std::string("K8s invalid capture version (") +
							  std::to_string(version) + ')');
	}
	m_capture_version = version;
}

inline int k8s_state_t::get_capture_version() const
{
	return m_capture_version;
}
