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

#include <sys/utsname.h>

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

falco::app::run_result falco::app::actions::print_support(falco::app::state& s)
{
	if(s.options.print_support)
	{
		nlohmann::json support;
		struct utsname sysinfo;
		std::string cmdline;

		if(uname(&sysinfo) != 0)
		{
			return run_result::fatal(std::string("Could not uname() to find system info: ") + strerror(errno));
		}

		const falco::versions_info infos(s.offline_inspector);
		support["version"] = infos.falco_version;
		support["engine_info"] = infos.as_json();

		support["system_info"]["sysname"] = sysinfo.sysname;
		support["system_info"]["nodename"] = sysinfo.nodename;
		support["system_info"]["release"] = sysinfo.release;
		support["system_info"]["version"] = sysinfo.version;
		support["system_info"]["machine"] = sysinfo.machine;
		support["cmdline"] = s.cmdline;
		support["config"] = read_file(s.options.conf_filename);
		support["rules_files"] = nlohmann::json::array();
		for(auto filename : s.config->m_loaded_rules_filenames)
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
