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
// k8s_event_handler.h
//

#pragma once

#include "json/json.h"
#include "sinsp_auth.h"
#include "k8s_handler.h"
#include "k8s_event_data.h"

class sinsp;

class k8s_event_handler : public k8s_handler
{
public:
	typedef user_event_filter_t::ptr_t filter_ptr_t;

	k8s_event_handler(k8s_state_t& state
#ifdef HAS_CAPTURE
		,ptr_t dependency_handler
		,collector_ptr_t collector = nullptr
		,std::string url = ""
		,const std::string& http_version = "1.1"
		,ssl_ptr_t ssl = 0
		,bt_ptr_t bt = 0
		,bool connect = true
		,bool blocking_socket = false
#endif // HAS_CAPTURE
		,filter_ptr_t event_filter = 0);

	~k8s_event_handler();

private:
	static std::string EVENT_FILTER;
	static std::string STATE_FILTER;

	bool handle_component(const Json::Value& json, const msg_data* data = 0);
	void handle_json(Json::Value&& root);

	filter_ptr_t m_event_filter;
	bool         m_event_ignored = false;
	bool         m_event_limit_exceeded = false;
};
