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

#include <sys/utsname.h>

#include "falco_engine_version.h"
#include "application.h"

using namespace falco::app;

static std::string read_file(const std::string &filename)
{
	std::ifstream t(filename);
	std::string str((std::istreambuf_iterator<char>(t)),
			std::istreambuf_iterator<char>());

	return str;
}

application::run_result application::print_support()
{
	if(m_options.print_support)
	{
		nlohmann::json support;
		struct utsname sysinfo;
		std::string cmdline;
		std::unique_ptr<sinsp> s(new sinsp());

		if(uname(&sysinfo) != 0)
		{
			return run_result::fatal(string("Could not uname() to find system info: ") + strerror(errno));
		}

		support["version"] = FALCO_VERSION;

		support["libs_version"] = FALCOSECURITY_LIBS_VERSION;
		support["plugin_api_version"] = application::get_plugin_api_version();
		
		support["driver_api_version"] = application::get_driver_api_version();
		support["driver_schema_version"] = application::get_driver_schema_version();
		support["default_driver_version"] = DRIVER_VERSION;

		support["system_info"]["sysname"] = sysinfo.sysname;
		support["system_info"]["nodename"] = sysinfo.nodename;
		support["system_info"]["release"] = sysinfo.release;
		support["system_info"]["version"] = sysinfo.version;
		support["system_info"]["machine"] = sysinfo.machine;
		support["cmdline"] = m_state->cmdline;
		support["engine_info"]["engine_version"] = FALCO_ENGINE_VERSION;
		support["config"] = read_file(m_options.conf_filename);
		support["rules_files"] = nlohmann::json::array();
		for(auto filename : m_state->config->m_loaded_rules_filenames)
		{
			nlohmann::json finfo;
			finfo["name"] = filename;
			nlohmann::json variant;
			variant["content"] = read_file(filename);
			finfo["variants"].push_back(variant);
			support["rules_files"].push_back(finfo);
		}
		printf("%s\n", support.dump().c_str());

		return run_result::exit();
	}

	return run_result::ok();
}
