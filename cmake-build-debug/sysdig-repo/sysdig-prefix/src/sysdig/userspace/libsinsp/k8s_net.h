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
// k8s_net.h
//
// connects and gets the data from k8s_net REST API interface
//
#pragma once

#ifdef HAS_CAPTURE

#include "k8s_component.h"
#include "k8s_event_data.h"
#include "k8s_handler.h"
#include "k8s_event_data.h"
#include "uri.h"
#include "sinsp_curl.h"
#include <sstream>
#include <utility>

class k8s;

class k8s_net
{
public:
	typedef sinsp_ssl::ptr_t              ssl_ptr_t;
	typedef sinsp_bearer_token::ptr_t     bt_ptr_t;
	typedef k8s_component::ext_list_ptr_t ext_list_ptr_t;
	typedef user_event_filter_t::ptr_t    filter_ptr_t;
	typedef k8s_handler::ptr_t            handler_ptr_t;
	typedef k8s_handler::collector_t      collector_t;
	typedef k8s_handler::collector_ptr_t  collector_ptr_t;

	k8s_net(k8s& kube, k8s_state_t& state, const std::string& uri = "http://localhost:80",
		ssl_ptr_t ssl = nullptr,
		bt_ptr_t bt = nullptr,
		filter_ptr_t event_filter = nullptr,
		bool blocking_sockets = false);

	~k8s_net();

	static handler_ptr_t make_handler(k8s_state_t& state, const k8s_component::type component, bool connect = true,
									 handler_ptr_t dep = std::make_shared<k8s_dummy_handler>(),
									 collector_ptr_t collector = nullptr, const std::string& urlstr = "",
									 ssl_ptr_t ssl = nullptr, bt_ptr_t bt = nullptr, bool blocking = false,
									 filter_ptr_t event_filter = nullptr);
	void add_handler(const k8s_component::type_map::value_type& component);
	bool has_handler(const k8s_component::type_map::value_type& component);
	bool has_dependency(const k8s_component::type_map::value_type& component);

	bool is_state_built(const k8s_component::type_map::value_type& component);

	void watch();
	void stop_watching();
	bool is_healthy() const;

	void set_machine_id(const std::string& machine_id);
	const std::string& get_machine_id() const;

	typedef k8s_handler::handler_t                       handler_t;
	typedef std::map<k8s_component::type, handler_ptr_t> handler_map_t;

	const handler_map_t& handlers() const;
	static handler_ptr_t get_handler(const handler_map_t& handlers, k8s_component::type component);
	static handler_ptr_t get_handler(const handler_map_t&  handlers, const k8s_component::type_map::value_type& component);
	static handler_ptr_t get_dependency_handler(const handler_map_t&  handlers, const k8s_component::type_map::value_type& component);
	static handler_ptr_t get_dependency_handler(const handler_map_t&  handlers, const k8s_component::type& component);

private:
	void init();
	bool is_secure();
	void cleanup();

	k8s_state_t&    m_state;
	collector_ptr_t m_collector;
	uri             m_uri;
	ssl_ptr_t       m_ssl;
	bt_ptr_t        m_bt;
	bool            m_stopped;
	handler_map_t   m_handlers;
	bool            m_blocking_sockets = false;
	filter_ptr_t    m_event_filter;
	std::string     m_machine_id;
};

inline bool k8s_net::is_secure()
{
	return m_uri.get_scheme() == "https";
}

inline bool k8s_net::is_healthy() const
{
	if(m_collector)
	{
		if (m_collector->get_steady_state())
		{
			return m_collector->subscription_count() == static_cast<int>(m_handlers.size());
		}
		else
		{
			return true;
		}
	}
	else
	{
		return false;
	}
}

inline bool k8s_net::has_handler(const k8s_component::type_map::value_type& component)
{
	auto it = m_handlers.find(component.first);
	return (it != m_handlers.end()) && it->second;
}

inline k8s_net::handler_ptr_t k8s_net::get_handler(const handler_map_t&  handlers, k8s_component::type component)
{
	auto it = handlers.find(component);
	if(it != handlers.end())
	{
		return it->second;
	}
	return nullptr;
}

inline k8s_net::handler_ptr_t k8s_net::get_handler(const handler_map_t&  handlers, const k8s_component::type_map::value_type& component)
{
	return get_handler(handlers, component.first);
}

inline bool k8s_net::is_state_built(const k8s_component::type_map::value_type& component)
{
	const auto& it = m_handlers.find(component.first);
	if(it != m_handlers.end())
	{
		return it->second && it->second->is_state_built();
	}
	return false;
}

inline void k8s_net::set_machine_id(const std::string& machine_id)
{
	m_machine_id = machine_id;
}

inline const std::string& k8s_net::get_machine_id() const
{
	return m_machine_id;
}

inline const k8s_net::handler_map_t& k8s_net::handlers() const
{
	return m_handlers;
}

#else // !HAS_CAPTURE

#include "k8s_component.h"
#include "k8s_handler.h"

namespace k8s_net
{
	k8s_handler::ptr_t make_handler(k8s_state_t& state, const k8s_component::type component, bool /*connect*/);
}

#endif // HAS_CAPTURE
