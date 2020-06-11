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
// sinsp_curl.h
//
// Curl utility
//

#if defined(__linux__)

#pragma once

#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_auth.h"
#include "uri.h"
#include "curl/curl.h"
#include <string>
#include <memory>

class sinsp_curl_http_headers
{
public:
	sinsp_curl_http_headers();
	~sinsp_curl_http_headers();

	void add(const string& header);
	
	struct curl_slist* ptr()
	{
		return m_curl_header_list;
	}

private:
	struct curl_slist* m_curl_header_list;
};

class sinsp_curl
{
public:
	typedef sinsp_ssl ssl;
	typedef sinsp_bearer_token bearer_token;

	static const long DEFAULT_TIMEOUT_MS = 5000L;

	sinsp_curl(const uri& url, long timeout_ms = DEFAULT_TIMEOUT_MS, bool debug = false);
	sinsp_curl(const uri& url, const std::string& bearer_token_file, long timeout_ms = DEFAULT_TIMEOUT_MS, bool debug = false);
	sinsp_curl(const uri& url,
		const std::string& cert, const std::string& key, const std::string& key_passphrase = "",
		const std::string& ca_cert = "", bool verify_peer = false, const std::string& cert_type = "PEM",
		const std::string& bearer_token_file = "",
		long timeout_ms = DEFAULT_TIMEOUT_MS,
		bool debug = false);
	sinsp_curl(const uri& url, ssl::ptr_t p_ssl = 0, bearer_token::ptr_t p_bt = 0,
				long timeout_ms = DEFAULT_TIMEOUT_MS, bool debug = false);

	~sinsp_curl();

	bool get_data(std::ostream& os);
	std::string get_data(bool do_log = true);

	void set_timeout(long seconds);
	long get_timeout() const;

	void set_url(const std::string& url);
	std::string get_url(bool show_creds = true) const;
	void set_body(const string& data);
	
	bool is_secure() const;
	ssl::ptr_t get_ssl();

	template<typename Opt, typename Arg>
	void setopt(Opt opt, Arg arg)
	{
		check_error(curl_easy_setopt(m_curl, opt, arg));
	}

	void enable_debug()
	{
		sinsp_curl::enable_debug(m_curl);
	}

	template<typename T>
	void add_header(T body)
	{
		m_headers.add(forward<T>(body));
	}

	static void init_ssl(CURL* curl, ssl::ptr_t ssl_data);
	bearer_token::ptr_t get_bt();
	static void init_bt(CURL* curl, bearer_token::ptr_t bt);

	static void enable_debug(CURL* curl, bool enable = true);
	static bool check_error(unsigned ret, bool exc = true);
	static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata);
	static bool is_redirect(long http_code);
	static bool handle_redirect(uri& url, std::string&& loc, std::ostream& os);
	static size_t write_data(void *ptr, size_t size, size_t nmemb, void *cb);

	const vector<string>& response_headers()
	{
		return m_response_headers;
	}

	long get_response_code() const
	{
		return m_response_code;
	}

private:
	struct data
	{
		char trace_ascii; // 1 or 0
	};
	static data m_config;
	static void dump(const char *text, unsigned char *ptr, size_t size, char nohex);
	static int trace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp);

	void init();

	CURL*               m_curl;
	uri                 m_uri;
	long                m_timeout_ms;
	ssl::ptr_t          m_ssl;
	bearer_token::ptr_t m_bt;
	bool                m_debug;
	char                m_redirect[CURL_MAX_HTTP_HEADER] = {0};
	stringstream        m_body;
	sinsp_curl_http_headers m_headers;
	vector<string>      m_response_headers;
	long                m_response_code;
};

inline void sinsp_curl::set_timeout(long milliseconds)
{
	m_timeout_ms = milliseconds;
}

inline long sinsp_curl::get_timeout() const
{
	return m_timeout_ms;
}

inline void sinsp_curl::set_url(const std::string& url)
{
	m_uri = url;
}

inline std::string sinsp_curl::get_url(bool show_creds) const
{
	return m_uri.to_string(show_creds);
}

inline bool sinsp_curl::is_secure() const
{
	return m_uri.is_secure();
}

inline sinsp_curl::ssl::ptr_t sinsp_curl::get_ssl()
{
	return m_ssl;
}

inline sinsp_curl::bearer_token::ptr_t sinsp_curl::get_bt()
{
	return m_bt;
}

#endif // __linux__
