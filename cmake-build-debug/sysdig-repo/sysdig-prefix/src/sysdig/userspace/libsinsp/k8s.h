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
// k8s.h
//
// extracts needed data from the k8s REST API interface
//

#pragma once

#include "json/json.h"
#include "k8s_component.h"
#include "k8s_state.h"
#include "k8s_event_data.h"
#include "k8s_net.h"
#include "sinsp_auth.h"
#include <sstream>
#include <utility>

class k8s_dispatcher;

class k8s
{
public:
#ifdef HAS_CAPTURE
	typedef sinsp_ssl::ptr_t          ssl_ptr_t;
	typedef sinsp_bearer_token::ptr_t bt_ptr_t;
#endif // HAS_CAPTURE

	typedef k8s_component::ext_list_ptr_t ext_list_ptr_t;
	typedef user_event_filter_t::ptr_t    filter_ptr_t;

	k8s(const std::string& uri = "http://localhost:80",
		bool is_captured = false,
#ifdef HAS_CAPTURE
		ssl_ptr_t ssl = 0,
		bt_ptr_t bt = 0,
		bool block = false,
#endif // HAS_CAPTURE
		filter_ptr_t event_filter = nullptr,
		ext_list_ptr_t extensions = nullptr,
		bool events_only = false);

	~k8s();

	std::size_t count(k8s_component::type component) const;

	void check_components();

	const k8s_state_t& get_state();
	void clear_events();
	void set_machine_id(const std::string& machine_id);
	std::string get_machine_id() const;

	void watch();
	void stop_watching();

	bool is_alive() const;

#ifdef HAS_CAPTURE
	typedef k8s_state_t::event_list_t event_list_t;
	const event_list_t& get_capture_events() const { return m_state.get_capture_events(); }
	std::string dequeue_capture_event() { return m_state.dequeue_capture_event(); }
#endif // HAS_CAPTURE

	// version:
	//   - 1 to support k8s events captured in old format (before refactoring)
	//   - 2 to support k8s events captured in new format (after refactoring)
	void simulate_watch_event(const std::string& json, int version = 2);

private:
	void stop_watch();

	void cleanup();

	k8s_state_t  m_state;
	filter_ptr_t m_event_filter;

	typedef std::map<k8s_component::type, std::unique_ptr<k8s_dispatcher>> dispatch_map_t;
	typedef std::map<k8s_component::type, std::shared_ptr<k8s_handler>> handler_map_t;
	// dispatch map is deprecated and serves only for backward compatibility with captures with old sysdig
	dispatch_map_t m_dispatch_map;
	handler_map_t  m_handler_map;

#ifdef HAS_CAPTURE
	k8s_net* m_net = nullptr;
#endif

	// a utility member containing pairs of enumerated values and component names
	static k8s_component::type_map m_components;
	friend class k8s_test;
};

inline bool k8s::is_alive() const
{
#ifdef HAS_CAPTURE
	ASSERT(m_net);
	return m_net->is_healthy();
#endif
	return true;
}

inline void k8s::clear_events()
{
	m_state.clear_events();
}

inline std::string k8s::get_machine_id() const
{
#ifdef HAS_CAPTURE
	if(m_net)
	{
		return m_net->get_machine_id();
	}
#endif // HAS_CAPTURE
	return "";
}

inline void k8s::set_machine_id(const std::string& machine_id)
{
#ifdef HAS_CAPTURE
	if(m_net)
	{
		m_net->set_machine_id(machine_id);
	}
	else
	{
		g_logger.log("K8s machine ID (MAC) setting attempted on null net object; "
					 "scope may not be available for events.",
					 sinsp_logger::SEV_WARNING);
	}
#endif // HAS_CAPTURE
}
