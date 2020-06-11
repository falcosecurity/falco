/*
Copyright (C) 2013-2019 Draios Inc dba Sysdig.

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

#include "container_engine/docker.h"

#include "runc.h"
#include "container_engine/mesos.h"
#include "sinsp.h"
#include "sinsp_int.h"

using namespace libsinsp::container_engine;
using namespace libsinsp::runc;

namespace {

size_t docker_curl_write_callback(const char* ptr, size_t size, size_t nmemb, string* json)
{
	const std::size_t total = size * nmemb;
	json->append(ptr, total);
	return total;
}

constexpr const cgroup_layout DOCKER_CGROUP_LAYOUT[] = {
	{"/", ""}, // non-systemd docker
	{"/docker-", ".scope"}, // systemd docker
	{nullptr, nullptr}
};
}

std::string docker::m_docker_sock = "/var/run/docker.sock";

void docker::cleanup()
{
	m_docker_info_source.reset(NULL);
}

void docker_async_source::init_docker_conn()
{
	if(!m_curlm)
	{
		m_curl = curl_easy_init();
		m_curlm = curl_multi_init();

		if(m_curlm)
		{
			curl_multi_setopt(m_curlm, CURLMOPT_PIPELINING, CURLPIPE_HTTP1|CURLPIPE_MULTIPLEX);
		}

		if(m_curl)
		{
			auto docker_path = scap_get_host_root() + m_docker_unix_socket_path;
			curl_easy_setopt(m_curl, CURLOPT_UNIX_SOCKET_PATH, docker_path.c_str());
			curl_easy_setopt(m_curl, CURLOPT_HTTPGET, 1);
			curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1);
			curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, docker_curl_write_callback);
		}
	}
}

void docker_async_source::free_docker_conn()
{
	if(m_curl)
	{
		curl_easy_cleanup(m_curl);
		m_curl = NULL;
	}

	if(m_curlm)
	{
		curl_multi_cleanup(m_curlm);
		m_curlm = NULL;
	}
}

std::string docker_async_source::build_request(const std::string &url)
{
	return "http://localhost" + m_api_version + url;
}

docker_async_source::docker_response docker_async_source::get_docker(const std::string& url, std::string &json)
{

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"docker_async (%s): Fetching url",
			url.c_str());

	if(curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str()) != CURLE_OK)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): curl_easy_setopt(CURLOPT_URL) failed",
				url.c_str());

		ASSERT(false);
		return docker_response::RESP_ERROR;
	}
	if(curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &json) != CURLE_OK)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): curl_easy_setopt(CURLOPT_WRITEDATA) failed",
				url.c_str());
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	if(curl_multi_add_handle(m_curlm, m_curl) != CURLM_OK)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): curl_multi_add_handle() failed",
				url.c_str());
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	while(true)
	{
		int still_running;
		CURLMcode res = curl_multi_perform(m_curlm, &still_running);
		if(res != CURLM_OK)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"docker_async (%s): curl_multi_perform() failed",
					url.c_str());

			ASSERT(false);
			return docker_response::RESP_ERROR;
		}

		if(still_running == 0)
		{
			break;
		}

		int numfds;
		res = curl_multi_wait(m_curlm, NULL, 0, 1000, &numfds);
		if(res != CURLM_OK)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"docker_async (%s): curl_multi_wait() failed",
					url.c_str());
			ASSERT(false);
			return docker_response::RESP_ERROR;
		}
	}

	if(curl_multi_remove_handle(m_curlm, m_curl) != CURLM_OK)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): curl_multi_remove_handle() failed",
				url.c_str());

		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	long http_code = 0;
	if(curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &http_code) != CURLE_OK)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): curl_easy_getinfo(CURLINFO_RESPONSE_CODE) failed",
				url.c_str());
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"docker_async (%s): http_code=%ld",
			url.c_str(), http_code);

	switch(http_code)
	{
		case 0: /* connection failed, apparently */
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"docker_async (%s): returning RESP_ERROR",
					url.c_str());
			return docker_response::RESP_ERROR;
		case 200:
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"docker_async (%s): returning RESP_OK",
					url.c_str());
			return docker_response::RESP_OK;
		default:
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"docker_async (%s): returning RESP_BAD_REQUEST",
					url.c_str());
			return docker_response::RESP_BAD_REQUEST;
	}

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"docker_async (%s): fallthrough, returning RESP_OK",
			url.c_str());

	return docker_response::RESP_OK;
}

bool docker::detect_docker(const sinsp_threadinfo *tinfo, std::string &container_id, std::string &container_name)
{
	if(matches_runc_cgroups(tinfo, DOCKER_CGROUP_LAYOUT, container_id))
	{
		// The container name is only available in windows
		container_name = s_incomplete_info_name;

		return true;
	}

	return false;
}
