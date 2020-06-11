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
// k8s_handler.h
//

#pragma once

#include "json/json.h"
#include "sinsp_auth.h"
#include "socket_collector.h"
#include "k8s_state.h"
#include "k8s_api_error.h"
#include <unordered_set>

class sinsp;

class k8s_handler
{
public:
	typedef k8s_component::msg_reason msg_reason;
	typedef k8s_component::msg_data msg_data;

	typedef std::shared_ptr<k8s_handler>   ptr_t;
	typedef std::vector<std::string>       uri_list_t;
	typedef std::shared_ptr<Json::Value>   json_ptr_t;
	typedef std::shared_ptr<k8s_api_error> api_error_ptr;
#ifdef HAS_CAPTURE
	typedef sinsp_ssl::ptr_t                             ssl_ptr_t;
	typedef sinsp_bearer_token::ptr_t                    bt_ptr_t;
	typedef socket_data_handler<k8s_handler>             handler_t;
	typedef handler_t::ptr_t                             handler_ptr_t;
	typedef socket_collector<handler_t>                  collector_t;
	typedef std::shared_ptr<socket_collector<handler_t>> collector_ptr_t;
#endif // HAS_CAPTURE

	static const int default_timeout_ms = 1000L;

	k8s_handler(const std::string& id,
		bool is_captured,
#ifdef HAS_CAPTURE
		std::string url,
		const std::string& path,
		const std::string& state_filter,
		const std::string& event_filter,
		const std::string& null_filter,
		collector_ptr_t collector = nullptr,
		const std::string& http_version = "1.1",
		int timeout_ms = default_timeout_ms,
		ssl_ptr_t ssl = nullptr,
		bt_ptr_t bt = nullptr,
		bool watch = true,
		bool connect = true,
		ptr_t dependency_handler = nullptr,
		bool blocking_socket = false,
#endif // HAS_CAPTURE
		unsigned max_messages = ~0,
		k8s_state_t* state = nullptr);

	virtual ~k8s_handler();

	bool connection_error() const;
	bool is_alive() const;
	bool ready() const;
	void set_event_json(json_ptr_t json, const std::string&);
	const std::string& get_id() const;
#ifdef HAS_CAPTURE
	handler_ptr_t handler();
#endif // HAS_CAPTURE
	std::string get_url() const;

	void collect_data();
	void set_machine_id(const std::string& machine_id);
	const std::string& get_machine_id() const;

	bool is_state_built() const;
	std::string name() const;
	api_error_ptr error() const;
	virtual void handle_json(Json::Value&& root);

	unsigned get_max_messages() const;
	void set_max_messages(unsigned max_msgs);

protected:
	typedef std::unordered_set<std::string> ip_addr_list_t;

	virtual bool handle_component(const Json::Value& json, const msg_data* data = 0) = 0;
	msg_data get_msg_data(const std::string& evt, const std::string& type, const Json::Value& root);
#ifdef HAS_CAPTURE
	static bool is_ip_address(const std::string& addr);
#endif // HAS_CAPTURE

	k8s_pair_list extract_object(const Json::Value& object);

	template <typename T>
	void handle_selectors(T& component, const Json::Value& selector)
	{
		if(!selector.isNull())
		{
			component.set_selectors(extract_object(selector));
		}
		else
		{
			g_logger.log("K8s Replication Controller: Null selector object.", sinsp_logger::SEV_ERROR);
		}
	}

	void log_event(const msg_data& data);
	void handle_error(const msg_data& data, const Json::Value& root, bool log = true);
	void log_error(const msg_data& data, const Json::Value& root);
	void log_not_found(const msg_data& data) const;

	k8s_state_t* m_state = nullptr;
	bool         m_state_built = false;
	bool         m_data_received = false;
	static std::string ERROR_FILTER;

private:
	typedef void (k8s_handler::*callback_func_t)(json_ptr_t, const std::string&);

	typedef std::vector<json_ptr_t> event_list_t;

#ifdef HAS_CAPTURE
	static ip_addr_list_t hostname_to_ip(const std::string& hostname);
#endif // HAS_CAPTURE

	bool connect();
	void make_http();
	void send_data_request();
	void receive_response();
	void check_enabled();
	void check_state();
	void check_collector_status();
	void process_events();

	const std::string& translate_name(const std::string& event_name);
	bool dependency_ready() const;

	std::string     m_id;
	std::string     m_machine_id;
#ifdef HAS_CAPTURE
	collector_ptr_t m_collector;
	handler_ptr_t   m_handler;
	std::string     m_path;
	std::string     m_state_filter;
	std::string     m_event_filter;
	std::string     m_null_filter;
	std::string*    m_filter;
	long            m_timeout_ms;
	std::string     m_url;
	bool            m_req_sent = false;
	bool            m_resp_recvd = false;
	json_query      m_jq;
	std::string     m_http_version;
	ssl_ptr_t       m_ssl;
	bt_ptr_t        m_bt;

	// some handlers only fetch state and die by design (eg. api or extensions handlers
	// have no need to continuously watch for updates)
	// this flag indicates whether handler should continue to watch after receiving
	// the initial state
	bool m_watch;
	bool m_watching = false; // indication of being in watch mode

	// flag indicating whether to connect to K8s API server (no connection needed when
	// replaying capture)
	bool m_connect;

	// k8s_handler on which this handler depends; the dependency handler must not be null and
	// it must have its state fully built before this handler can begin building its own state
	ptr_t m_dependency_handler;

	bool m_blocking_socket = false;

#endif // HAS_CAPTURE

	// limits the number of messages handled in single cycle
	unsigned m_max_messages = ~0;
	bool m_state_processing_started = false;

	event_list_t m_events;

	// error indicating something went wrong with the K8s component handled by this handler
	// this error is later examined by k8s::check_components() and if it is
	// HTTP status > 400, one of the following actions is taken:
	//  - if component is critical for consistent k8s state (eg. namespace, node, pod),
	//    exception is thrown and, consequently, the whole k8s framework will be destroyed
	//  - if component is not critical (eg. extensions like daemonset or deployment),
	//    error is logged and handler is destroyed, but the k8s framework continues to
	//    exist without it, only receiving data for existing components
	api_error_ptr m_error;

	// this capture flag does not indicate whether we are in global capture mode,
	// it is only an indication of whether this handler data should be captured
	// at all (eg. there is no need to capture api or extensions detection data)
	//
	// global capture flag is checked in the k8s state call
	bool m_is_captured = false;

	bool m_connect_logged = false;
};

inline unsigned k8s_handler::get_max_messages() const
{
	return m_max_messages;
}

inline void k8s_handler::set_max_messages(unsigned max_msgs)
{
	m_max_messages = max_msgs;
}

#ifdef HAS_CAPTURE
inline k8s_handler::handler_ptr_t k8s_handler::handler()
{
	return m_handler;
}
#endif // HAS_CAPTURE

inline std::string k8s_handler::get_url() const
{
#ifdef HAS_CAPTURE
	return m_url;
#else
	return "";
#endif
}

inline const std::string& k8s_handler::get_id() const
{
	return m_id;
}

inline void k8s_handler::set_machine_id(const std::string& machine_id)
{
	m_machine_id = machine_id;
}

inline const std::string& k8s_handler::get_machine_id() const
{
	return m_machine_id;
}

inline bool k8s_handler::ready() const
{
	return m_data_received;
}

inline bool k8s_handler::is_state_built() const
{
	return m_state_built;
}

inline void k8s_handler::log_event(const msg_data& data)
{
	g_logger.log("K8s " + data.get_reason_desc() + ' ' +
				 data.m_kind + ' ' +
				 data.m_name + " [" + data.m_uid + "]",
				 sinsp_logger::SEV_DEBUG);
}

inline void k8s_handler::log_not_found(const msg_data& data) const
{
	g_logger.log("K8s " + name() + " not found [" + data.m_uid + "]: " + data.m_name,
				 sinsp_logger::SEV_ERROR);
}

inline k8s_handler::api_error_ptr k8s_handler::error() const
{
	return m_error;
}

// This dummy class serves only as a dependency stand-in for handlers
// which have no dependencies (eg. nodes handler, which is first populated
// into the state and has no dependency; or special-purpose handlers,
// such as delegator, api handler etc), but the logic requires a non-null
// pointer to handler to determine whether dependency is ready; to avoid
// special-casing eg. nodes handler all over the place, we use this dummy
// liar, always returning true for its state being built, as the dependency
class k8s_dummy_handler : public k8s_handler
{
public:
	k8s_dummy_handler(): k8s_handler("k8s_dummy_handler", false,
#ifdef HAS_CAPTURE
									 "", "", "", "",  "", nullptr,
									 "", 0, nullptr, nullptr,
									 false, false, nullptr, false,
#endif // HAS_CAPTURE
									 ~0, nullptr)
	{
		m_state_built = true;
	}

private:
	virtual bool handle_component(const Json::Value& json, const msg_data* data = 0)
	{
		return false;
	};
};
