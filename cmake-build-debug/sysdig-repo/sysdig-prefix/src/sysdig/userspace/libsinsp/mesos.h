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
// mesos.h
//

#pragma once

#include "json/json.h"
#include "mesos_auth.h"
#include "mesos_common.h"
#include "mesos_component.h"
#include "mesos_http.h"
#include "marathon_http.h"
#include "mesos_state.h"
#include "mesos_collector.h"
#include "uri.h"
#include <sstream>
#include <utility>
#include <unordered_map>

class mesos : public mesos_auth
{
public:

#ifdef HAS_CAPTURE
	typedef mesos_http::marathon_uri_t uri_list_t;
#else
	typedef std::vector<std::string> uri_list_t;
#endif // HAS_CAPTURE
	typedef std::shared_ptr<Json::Value> json_ptr_t;
	typedef uri::credentials_t credentials_t;
	typedef std::shared_ptr<uri::credentials_t> uri_creds_ptr_t;

	static const std::string default_state_uri;
	static const std::string default_state_api;
	static const std::string default_marathon_uri;
	static const std::string default_groups_api;
	static const std::string default_apps_api;
	static const std::string default_watch_api;
	static const std::string default_version_api;
	static const int default_timeout_ms;

	// constructor for testing only, not to be used in production
	mesos(const std::string& mesos_state_json,
		const std::string& marathon_groups_json,
		const std::string& marathon_apps_json);

	mesos(const std::string& state_uri,
		const uri_list_t& marathon_uris = uri_list_t(),
		bool discover_mesos_leader = false,
		bool discover_marathon_leader = false,
		const credentials_t& mesos_credentials = credentials_t(),
		const credentials_t& marathon_credentials = credentials_t(),
		int timeout_ms = default_timeout_ms,
		bool is_captured = false,
		bool verbose = false);

	mesos(const std::string& state_uri,
		const uri_list_t& marathon_uris = uri_list_t(),
		bool discover_mesos_leader = false,
		bool discover_marathon_leader = false,
		const credentials_t& dcos_enterprise_credentials = credentials_t(),
		int timeout_ms = default_timeout_ms,
		bool is_captured = false,
		bool verbose = false);

	virtual ~mesos();

	const mesos_state_t& get_state() const;
	bool is_alive() const;
	void refresh();
	void clear_mesos();

	bool has_marathon() const;
	void clear_marathon();

	void simulate_event(const std::string& json);
	bool collect_data();
	virtual void refresh_token();

#ifdef HAS_CAPTURE
	const uri_list_t &marathon_uris();

	void send_data_request(bool collect = true);

	const mesos_state_t::capture_list& get_capture_events() const;
	std::string dequeue_capture_event();

private:
	void send_mesos_data_request();
	void connect_mesos();
	void check_collector_status(int expected);
	void send_marathon_data_request();
	void connect_marathon();

	template <typename T>
	bool connect(T http, typename T::element_type::callback_func_t func, int expected_connections)
	{
		if(http)
		{
			if(m_collector.has(http))
			{
				if(!http->is_connected())
				{
					m_collector.remove(http);
				}
			}
			if(!m_collector.has(http))
			{
				http->set_parse_func(func);
				m_collector.add(http);
			}
			check_collector_status(expected_connections);
			return m_collector.has(http);
		}
		return false;
	}
	void capture_frameworks(const Json::Value& root, Json::Value& capture);
	void capture_slaves(const Json::Value& root, Json::Value& capture);

	typedef std::unordered_map<std::string, marathon_http::ptr_t> marathon_http_map;

	void remove_framework_http(marathon_http_map& http_map, const std::string& framework_id);

	mesos_http::ptr_t m_state_http;
	marathon_http_map m_marathon_groups_http;
	marathon_http_map m_marathon_apps_http;
	mesos_collector   m_collector;
	std::string       m_mesos_uri;
	uri_list_t        m_marathon_uris;
#endif // HAS_CAPTURE

private:
	void init();
	void init_marathon();
	void rebuild_mesos_state(bool full = false);
	void rebuild_marathon_state(bool full = false);

	void handle_frameworks(const Json::Value& root);
	void add_framework(const Json::Value& framework);
	void add_tasks(mesos_framework& framework, const Json::Value& f_val);
	void add_tasks_impl(mesos_framework& framework, const Json::Value& tasks);
	void handle_slaves(const Json::Value& root);
	void add_slave(const Json::Value& framework);

	void check_frameworks(const json_ptr_t& json);
	void set_state_json(json_ptr_t json, const std::string& dummy = "");
	void parse_state(Json::Value&& root);
	void parse_state(json_ptr_t json, const std::string&);
	void set_marathon_groups_json(json_ptr_t json, const std::string& framework_id);
	void parse_groups(json_ptr_t json, const std::string& framework_id);
	void parse_groups(Json::Value&& json, const std::string& framework_id);
	void set_marathon_apps_json(json_ptr_t json, const std::string& framework_id);
	void parse_apps(json_ptr_t json, const std::string& framework_id);
	void parse_apps(Json::Value&& json, const std::string& framework_id);
	void remove_framework(const Json::Value& framework);

	mesos_state_t m_state;
	bool          m_creation_logged = false;
	bool          m_discover_mesos_leader;
	bool          m_discover_marathon_uris;
	long          m_timeout_ms;
	bool          m_verbose = false;

	typedef std::map<std::string, json_ptr_t> json_map_type_t;
	json_ptr_t         m_mesos_state_json;
	json_map_type_t    m_marathon_groups_json;
	json_map_type_t    m_marathon_apps_json;
	time_t             m_last_mesos_refresh = 0;
	time_t             m_last_marathon_refresh = 0;
	bool               m_json_error = false;
	bool               m_testing = false;
	uri::credentials_t m_mesos_credentials;
	uri::credentials_t m_marathon_credentials;

	typedef std::unordered_set<std::string> framework_list_t;
	framework_list_t m_inactive_frameworks;
	framework_list_t m_activated_frameworks;

	static const mesos_component::component_map m_components;

	friend class mesos_http;
	friend class marathon_http;
};

inline const mesos_state_t& mesos::get_state() const
{
	return m_state;
}

inline bool mesos::has_marathon() const
{
#ifdef HAS_CAPTURE
	if(m_testing)
	{
		return true;
	}
	else
	{
		return m_marathon_groups_http.size() || m_marathon_apps_http.size();
	}
#else
	return false;
#endif
}

#ifdef HAS_CAPTURE

inline const mesos_state_t::capture_list& mesos::get_capture_events() const
{
	return m_state.get_capture_events();
}

inline std::string mesos::dequeue_capture_event()
{
	return m_state.dequeue_capture_event();
}

#endif // HAS_CAPTURE

inline void mesos::clear_mesos()
{
	m_state.clear_mesos();
}

inline void mesos::clear_marathon()
{
	m_state.clear_marathon();
}

inline void mesos::parse_apps(json_ptr_t json, const std::string& framework_id)
{
	m_state.parse_apps(std::move(json), framework_id);
}

inline void mesos::parse_groups(json_ptr_t json, const std::string& framework_id)
{
	m_state.parse_groups(std::move(json), framework_id);
}

inline void mesos::parse_apps(Json::Value&& json, const std::string& framework_id)
{
	m_state.parse_apps(std::move(json), framework_id);
}

inline void mesos::parse_groups(Json::Value&& json, const std::string& framework_id)
{
	m_state.parse_groups(std::move(json), framework_id);
}
