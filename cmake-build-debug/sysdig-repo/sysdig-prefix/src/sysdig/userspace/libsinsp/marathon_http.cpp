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
// marathon_http.cpp
//
#ifndef CYGWING_AGENT

#ifdef HAS_CAPTURE

#include "marathon_http.h"
#include "curl/curl.h"
#include "curl/easy.h"
#define BUFFERSIZE 512 // b64 needs this macro
#include "b64/encode.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "json_error_log.h"
#include "mesos.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <unistd.h>

marathon_http::marathon_http(mesos& m, const uri& url, bool discover_marathon, int timeout_ms, const string& token):
	mesos_http(m, url, false, discover_marathon, timeout_ms, token)
{
	g_logger.log("Creating Marathon HTTP object for [" + url.to_string(false) + "] ...", sinsp_logger::SEV_DEBUG);
	if(refresh_data())
	{
		g_logger.log("Created Marathon HTTP connection (" + url.to_string(false) + ") for framework [" +
					 get_framework_name() + "] (" + get_framework_id() + "), version: " + get_framework_version(),
					 sinsp_logger::SEV_INFO);
	}
	else
	{
		throw sinsp_exception("Could not obtain Mesos Marathon framework information.");
	}

	g_logger.log("Marathon request [" + get_request() + ']', sinsp_logger::SEV_DEBUG);
}

marathon_http::~marathon_http()
{
}

bool marathon_http::refresh_data()
{
	std::ostringstream os;
	std::string uri = make_uri("/v2/info");
	CURLcode res = get_data(uri, os);

	if(res != CURLE_OK)
	{
		std::string errstr = std::string("Problem accessing /v2/info: ") + curl_easy_strerror(res);
		g_logger.log(errstr, sinsp_logger::SEV_ERROR);
		g_json_error_log.log(os.str(), errstr, sinsp_utils::get_current_time_ns(), uri);
		return false;
	}

	try
	{
		Json::Value root;
		Json::Reader reader;
		if(reader.parse(os.str(), root, false))
		{
			set_framework_id(get_json_string(root, "frameworkId"));
			set_framework_name(get_json_string(root, "name"));
			set_framework_version(get_json_string(root, "version"));
			g_logger.log("Found Marathon framework: " + get_framework_name() + " (" + get_framework_id() + "), version: " + get_framework_version(), sinsp_logger::SEV_DEBUG);
		}
		else
		{
			std::string errstr;
			errstr = reader.getFormattedErrorMessages();
			g_logger.log("Error parsing framework info (" + errstr + ").\nJSON:\n---\n" + os.str() + "\n---", sinsp_logger::SEV_ERROR);
			g_json_error_log.log(os.str(), errstr, sinsp_utils::get_current_time_ns(), uri);
			return false;
		}
	}
	catch(const std::exception& ex)
	{
		std::string errstr = std::string("Error parsing framework info:") + ex.what();
		g_logger.log(errstr, sinsp_logger::SEV_ERROR);
		g_json_error_log.log(os.str(), errstr, sinsp_utils::get_current_time_ns(), uri);
		return false;
	}
	
	return true;
}

std::string marathon_http::get_groups(const std::string& group_id)
{
	std::ostringstream os;
	std::string uri = make_uri("/v2/groups" + group_id);
	CURLcode res = get_data(uri, os);

	if(res != CURLE_OK)
	{
		std::string errstr = std::string("Problem accessing /v2/groups: ") + curl_easy_strerror(res);
		g_logger.log(errstr, sinsp_logger::SEV_ERROR);
		g_json_error_log.log(os.str(), errstr, sinsp_utils::get_current_time_ns(), uri);
		return "";
	}

	return os.str();
}

#endif // HAS_CAPTURE
#endif // CYGWING_AGENT
