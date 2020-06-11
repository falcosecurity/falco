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
#ifdef CYGWING_AGENT

#include "container_engine/docker.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "dragent_win_hal_public.h"

using namespace libsinsp::container_engine;

docker::docker(container_cache_interface& cache, const wmi_handle_source& wmi_source) :
   container_engine_base(cache),
   m_wmi_handle_source(wmi_source)
{
}

void docker::cleanup()
{
	g_docker_info_source.reset(NULL);
}

void docker_async_source::init_docker_conn()
{
}

void docker_async_source::free_docker_conn()
{
}

std::string docker_async_source::build_request(const std::string &url)
{
	return "GET " + m_api_version + url + " HTTP/1.1\r\nHost: docker\r\n\r\n";
}

bool docker::detect_docker(sinsp_threadinfo *tinfo, std::string &container_id, std::string &container_name)
{
	wh_docker_container_info wcinfo = wh_docker_resolve_pid(m_wmi_handle_source.get_wmi_handle(), tinfo->m_pid);
	if(!wcinfo.m_res)
	{
		return false;
	}

	container_id = wcinfo.m_container_id;
	container_name = wcinfo.m_container_name;

	return true;
}

docker_async_source::docker_response docker_async_source::get_docker(const std::string& url, std::string &json)
{
	const char* response = NULL;
	bool qdres = wh_query_docker(m_inspector->get_wmi_handle(),
				     (char*)url.c_str(),
				     &response);
	if(qdres == false)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	json = response;
	if(strncmp(json.c_str(), "HTTP/1.0 200 OK", sizeof("HTTP/1.0 200 OK") -1))
	{
		return docker_response::RESP_BAD_REQUEST;
	}

	size_t pos = json.find("{");
	if(pos == string::npos)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}
	json = json.substr(pos);

	return docker_response::RESP_OK;
}

#endif // CYGWING_AGENT
