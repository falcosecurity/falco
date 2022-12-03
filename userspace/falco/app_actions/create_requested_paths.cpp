/*
Copyright (C) 2022 The Falco Authors.

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

#include "application.h"
#include "falco_utils.h"
#include <sys/stat.h>

#ifndef CPPPATH_SEP
#ifdef _MSC_VER
#define CPPPATH_SEP "\\"
#else
#define CPPPATH_SEP "/"
#endif
#endif

using namespace falco::app;

application::run_result application::create_requested_paths()
{
	if(!m_options.gvisor_config.empty())
	{
		// This is bad: parsing gvisor config to get endpoint
		// to be able to auto-create the path to the file for the user.
		std::ifstream reader(m_options.gvisor_config);
		if (reader.fail())
		{
			return run_result::fatal(m_options.gvisor_config + ": cannot open file");
		}

		nlohmann::json parsed_json;
		std::string gvisor_socket;
		try
		{
			parsed_json = nlohmann::json::parse(reader);
		}
		catch (const std::exception &e)
		{
			return run_result::fatal(m_options.gvisor_config + ": cannot parse JSON: " + e.what());
		}

		try
		{
			gvisor_socket = parsed_json["trace_session"]["sinks"][0]["config"]["endpoint"];
		}
		catch (const std::exception &e)
		{
			return run_result::fatal(m_options.gvisor_config + ": failed to fetch config.endpoint: " + e.what());
		}

		int ret = create_dir(gvisor_socket);
		if (ret != 0)
		{
			return run_result::fatal(gvisor_socket + ": " + strerror(errno));
		}
	}

	if (m_state->config->m_grpc_enabled && !m_state->config->m_grpc_bind_address.empty())
	{
		if(falco::utils::network::is_unix_scheme(m_state->config->m_grpc_bind_address))
		{
			auto server_path = m_state->config->m_grpc_bind_address.substr(
				falco::utils::network::UNIX_SCHEME.length()
			);
			int ret = create_dir(server_path);
			if(ret != 0)
			{
				return run_result::fatal(server_path + ": " + strerror(errno));
			}
		}
	}

	// TODO: eventually other files written by Falco whose destination is
	// customizable by users, must be handled here.
	return run_result::ok();
}

int application::create_dir(const std::string &path)
{
	// Properly reset errno
	errno = 0;

	std::istringstream f(path);
	std::string path_until_token;
	std::string s;
	// Create all the subfolder stopping at last token (f.eof());
	// Examples:
	// "/tmp/foo/bar" -> "", "tmp", "foo" -> mkdir("/") + mkdir("/tmp/") + midir("/tmp/foo/")
	// "tmp/foo/bar" -> "tmp", "foo" -> mkdir("tmp/") + midir("tmp/foo/")
	while (getline(f, s, *CPPPATH_SEP) && !f.eof()) {
		path_until_token += s + CPPPATH_SEP;
		int ret = mkdir(path_until_token.c_str(), 0600);
		if (ret != 0 && errno != EEXIST)
		{
			return ret;
		}
	}
	return 0;
}
