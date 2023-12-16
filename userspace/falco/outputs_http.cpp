// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors

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

#include "outputs_http.h"
#include "logger.h"

#define CHECK_RES(fn) res = res == CURLE_OK ? fn : res

static size_t noop_write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	// We don't want to echo anything. Just return size of bytes ignored
	return size * nmemb;
}

bool falco::outputs::output_http::init(const config& oc, bool buffered, const std::string& hostname, bool json_output, std::string &err)
{
	if (!falco::outputs::abstract_output::init(oc, buffered, hostname, json_output, err)) {
		return false;
	}

	m_curl = nullptr;
	m_http_headers = nullptr;
	CURLcode res = CURLE_FAILED_INIT;

	m_curl = curl_easy_init();
	if(!m_curl)
	{
		falco_logger::log(falco_logger::level::ERR, "libcurl failed to initialize the handle: " + std::string(curl_easy_strerror(res)));
		return false;
	}
	if(m_json_output)
	{
		m_http_headers = curl_slist_append(m_http_headers, "Content-Type: application/json");
	}
	else
	{
		m_http_headers = curl_slist_append(m_http_headers, "Content-Type: text/plain");
	}
	res = curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, m_http_headers);
	
	// if the URL is quoted the quotes should be removed to satisfy libcurl expected format
	std::string unquotedUrl = m_oc.options["url"];
	if (!unquotedUrl.empty() && (
		(unquotedUrl.front() == '\"' && unquotedUrl.back() == '\"') ||
		(unquotedUrl.front() == '\'' && unquotedUrl.back() == '\'')
	))
	{
		unquotedUrl = libsinsp::filter::unescape_str(unquotedUrl);
	}
	CHECK_RES(curl_easy_setopt(m_curl, CURLOPT_URL, unquotedUrl.c_str()));

	CHECK_RES(curl_easy_setopt(m_curl, CURLOPT_USERAGENT, m_oc.options["user_agent"].c_str()));
	CHECK_RES(curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE, -1L));

	if(m_oc.options["insecure"] == std::string("true"))
	{
		CHECK_RES(curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYPEER, 0L));
		CHECK_RES(curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYHOST, 0L));
	}

	if(m_oc.options["mtls"] == std::string("true"))
	{
		CHECK_RES(curl_easy_setopt(m_curl, CURLOPT_SSLCERT, m_oc.options["client_cert"].c_str()));
		CHECK_RES(curl_easy_setopt(m_curl, CURLOPT_SSLKEY, m_oc.options["client_key"].c_str()));
	}

	if (!m_oc.options["ca_cert"].empty())
	{
		CHECK_RES(curl_easy_setopt(m_curl, CURLOPT_CAINFO, m_oc.options["ca_cert"].c_str()));
	}
	else if(!m_oc.options["ca_bundle"].empty())
	{
		CHECK_RES(curl_easy_setopt(m_curl, CURLOPT_CAINFO, m_oc.options["ca_bundle"].c_str()));
	}
	else
	{
		CHECK_RES(curl_easy_setopt(m_curl, CURLOPT_CAPATH, m_oc.options["ca_path"].c_str()));
	}

	if(m_oc.options["echo"] == std::string("false"))
	{
		// If echo==true, libcurl defaults to fwrite to stdout, ie: echoing
		CHECK_RES(curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, noop_write_callback));
	}

	if(m_oc.options["compress_uploads"] == std::string("true"))
	{
		CHECK_RES(curl_easy_setopt(m_curl, CURLOPT_TRANSFER_ENCODING, 1L));
	}

	if(m_oc.options["keep_alive"] == std::string("true"))
	{
		CHECK_RES(curl_easy_setopt(m_curl, CURLOPT_TCP_KEEPALIVE, 1L));
	}

	if(res != CURLE_OK)
	{
		err = "libcurl error: " + std::string(curl_easy_strerror(res));
		return false;
	}
	return true;
}

void falco::outputs::output_http::output(const message *msg)
{
	CURLcode res = curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS, msg->msg.c_str());
	CHECK_RES(curl_easy_perform(m_curl));
	if(res != CURLE_OK)
	{
		falco_logger::log(falco_logger::level::ERR, "libcurl failed to perform call: " + std::string(curl_easy_strerror(res)));
	}
}

void falco::outputs::output_http::cleanup()
{
	curl_easy_cleanup(m_curl);
	m_curl = nullptr;
	curl_slist_free_all(m_http_headers);
	m_http_headers = nullptr;
}
