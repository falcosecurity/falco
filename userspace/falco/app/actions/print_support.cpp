// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#ifndef _WIN32
#include <sys/utsname.h>
#else
#include <windows.h>
#endif
#include <iostream>

#include "actions.h"
#include "../../versions_info.h"

using namespace falco::app;
using namespace falco::app::actions;

static std::string read_file(const std::string &filename)
{
	std::ifstream t(filename);
	std::string str((std::istreambuf_iterator<char>(t)),
			std::istreambuf_iterator<char>());

	return str;
}

#ifndef _WIN32
static int get_sysinfo(nlohmann::json &support)
{
	struct utsname sysinfo;
	if(uname(&sysinfo) != 0)
	{
		return -1;
	}

	support["system_info"]["sysname"] = sysinfo.sysname;
	support["system_info"]["nodename"] = sysinfo.nodename;
	support["system_info"]["release"] = sysinfo.release;
	support["system_info"]["version"] = sysinfo.version;
	support["system_info"]["machine"] = sysinfo.machine;
	return 0;
}
#else
static int get_sysinfo(nlohmann::json &support)
{
	OSVERSIONINFO osvi;
	SYSTEM_INFO sysInfo;
	TCHAR computerName[256];
	DWORD size = sizeof(computerName);

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetSystemInfo(&sysInfo);
	if(!GetVersionEx(&osvi) || !GetComputerName(computerName, &size))
	{
		return -1;
	}

	support["system_info"]["sysname"] = "Windows";
	support["system_info"]["nodename"] = computerName;
	support["system_info"]["release"] = osvi.dwMajorVersion;
	support["system_info"]["version"] = osvi.dwMinorVersion;

	switch (sysInfo.wProcessorArchitecture) {
		case PROCESSOR_ARCHITECTURE_AMD64:
			support["system_info"]["machine"] = "x86_64";
			break;
		case PROCESSOR_ARCHITECTURE_ARM:
			support["system_info"]["machine"] = "ARM";
			break;
		case PROCESSOR_ARCHITECTURE_ARM64:
			support["system_info"]["machine"] = "ARM64";
			break;
		case PROCESSOR_ARCHITECTURE_INTEL:
			support["system_info"]["machine"] = "i386";
			break;
		default:
			support["system_info"]["machine"] = "unknown";
	}
	return 0;
}
#endif

falco::app::run_result falco::app::actions::print_support(falco::app::state& s)
{
	if(s.options.print_support)
	{
		nlohmann::json support;

		if(get_sysinfo(support) != 0)
		{
			return run_result::fatal(std::string("Could not get system info: ") + strerror(errno));
		}

		const falco::versions_info infos(s.offline_inspector);
		support["version"] = infos.falco_version;
		support["engine_info"] = infos.as_json();
		support["cmdline"] = s.cmdline;
		support["config"] = read_file(s.options.conf_filename);
		support["rules_files"] = nlohmann::json::array();
		for(const auto& filename : s.config->m_loaded_rules_filenames)
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
