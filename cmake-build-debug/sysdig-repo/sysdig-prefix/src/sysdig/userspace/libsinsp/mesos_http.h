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
// mesos_http.h
//

#pragma once

#ifdef HAS_CAPTURE

#include "curl/curl.h"
#include "uri.h"
#include "json/json.h"
#include <iostream>
#include <string>
#include <memory>
#include <algorithm>
#include "sinsp_curl.h"
#include "json_error_log.h"

class mesos;

class mesos_http
{
public:
	typedef std::shared_ptr<mesos_http> ptr_t;
	typedef std::shared_ptr<Json::Value> json_ptr_t;
	typedef void (mesos::*callback_func_t)(json_ptr_t, const std::string&);
	typedef std::vector<std::string> marathon_uri_t;

	mesos_http(mesos& m, const uri& url,
				bool discover_mesos_lead_master = false,
				bool discover_marathon = false,
				int timeout_ms = 5000L,
				const string& token = "");

	virtual ~mesos_http();

	bool get_all_data(callback_func_t);

	virtual int get_socket(long timeout_ms = -1);

	virtual bool is_connected() const;

	virtual bool on_data();

	virtual void on_error(const std::string& err, bool disconnect);

	const uri& get_url() const;
	const std::string& get_request() const;

	std::string make_uri(const std::string& path);

	Json::Value get_task_labels(const std::string& task_id);

	void set_parse_func(callback_func_t parse);

	const std::string& get_framework_id() const;
	void set_framework_id(const std::string& id);
	const std::string& get_framework_name() const;
	void set_framework_name(const std::string& id);
	const std::string& get_framework_version() const;
	void set_framework_version(const std::string& id);

	const marathon_uri_t& get_marathon_uris() const;
	void set_token(const string& token);

protected:
	CURL* get_sync_curl();
	CURL* get_select_curl();
	mesos& get_mesos();
	CURLcode get_data(const std::string& url, std::ostream& os);
	void check_error(CURLcode res);
	void cleanup();
	void cleanup(CURL**);
	int wait(int for_recv);

	callback_func_t get_parse_func();
	std::string make_request(uri url, curl_version_info_data* m_curl_version = 0);
	static json_ptr_t try_parse(const std::string& json, const std::string &uri);
	static bool is_framework_active(const Json::Value& framework);
	std::string get_framework_url(const Json::Value& framework);

private:
	void discover_mesos_leader();
	Json::Value get_state_frameworks();
	void discover_framework_uris(const Json::Value& frameworks);

	void send_request();

	CURL*                   m_sync_curl;
	CURL*                   m_select_curl;
	mesos&                  m_mesos;
	std::string             m_protocol;
	uri                     m_url;
	bool                    m_connected;
	curl_socket_t           m_watch_socket;
	long                    m_timeout_ms;
	callback_func_t         m_callback_func;
	std::string             m_data_buf;
	std::string             m_framework_id;
	std::string             m_framework_name;
	std::string             m_framework_version;
	curl_version_info_data* m_curl_version;
	std::string             m_request;
	bool                    m_is_mesos_state;
	marathon_uri_t          m_marathon_uris;
	bool                    m_discover_lead_master;
	bool                    m_discover_marathon;
	//bool                    m_redirect = false;
	std::string::size_type  m_content_length = std::string::npos;
	char                    m_redirect[CURL_MAX_HTTP_HEADER] = {0};
	string                  m_token;
	sinsp_curl_http_headers m_sync_curl_headers;

	friend class mesos;

	void extract_data(std::string& data);
	void handle_data();
	bool detect_chunked_transfer(const std::string& data);
	void handle_json(std::string::size_type end_pos, bool chunked);
};

inline bool mesos_http::is_connected() const
{
	return m_connected;
}

inline const uri& mesos_http::get_url() const
{
	return m_url;
}

inline CURL* mesos_http::get_sync_curl()
{
	return m_sync_curl;
}

inline CURL* mesos_http::get_select_curl()
{
	return m_select_curl;
}

inline mesos& mesos_http::get_mesos()
{
	return m_mesos;
}

inline const std::string& mesos_http::get_request() const
{
	return m_request;
}

inline void mesos_http::set_parse_func(callback_func_t parse)
{
	m_callback_func = parse;
}

inline mesos_http::callback_func_t mesos_http::get_parse_func()
{
	return m_callback_func;
}

inline mesos_http::json_ptr_t mesos_http::try_parse(const std::string& json, const std::string &uri)
{
	json_ptr_t root(new Json::Value());
	try
	{
		if(Json::Reader().parse(json, *root))
		{
			return root;
		}
		else
		{
			std::string errstr;
			errstr = Json::Reader().getFormattedErrorMessages();
			g_logger.log("mesos_http::try_parse could not parse json (" + errstr + ")", sinsp_logger::SEV_WARNING);
			g_json_error_log.log(json, errstr, sinsp_utils::get_current_time_ns(), uri);
		}
	}
	catch(const Json::Exception &e)
	{
		g_logger.log("Could not parse JSON document: " + string(e.what()), sinsp_logger::SEV_WARNING);
		g_json_error_log.log(json, e.what(), sinsp_utils::get_current_time_ns(), uri);
	}
	catch(...) { }
	return nullptr;
}

inline const std::string& mesos_http::get_framework_id() const
{
	return m_framework_id;
}

inline void mesos_http::set_framework_id(const std::string& id)
{
	m_framework_id = id;
}

inline const std::string& mesos_http::get_framework_name() const
{
	return m_framework_name;
}

inline void mesos_http::set_framework_name(const std::string& name)
{
	m_framework_name = name;
}

inline const std::string& mesos_http::get_framework_version() const
{
	return m_framework_version;
}

inline void mesos_http::set_framework_version(const std::string& version)
{
	m_framework_version = version;
}

inline const mesos_http::marathon_uri_t& mesos_http::get_marathon_uris() const
{
	return m_marathon_uris;
}

#else // !HAS_CAPTURE

#include "json/json.h"
#include <memory>

class mesos_http
{
public:
	typedef std::shared_ptr<Json::Value> json_ptr_t;
	static json_ptr_t try_parse(const std::string& json, const std::string &uri)
	{
		json_ptr_t root(new Json::Value());
		try
		{
			if(Json::Reader().parse(json, *root))
			{
				return root;
			}
		}
		catch(...) { }
		return nullptr;
	}
};

#endif // HAS_CAPTURE
