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

#include <nlohmann/json.hpp>

#include "config_falco.h"
#include "application.h"
#include "falco_engine_version.h"

using namespace falco::app;

application::run_result application::print_version()
{
	if(m_options.print_version_info)
	{
		std::unique_ptr<sinsp> s(new sinsp());
		printf("Falco version: %s\n", FALCO_VERSION);
		printf("Libs version:  %s\n", FALCOSECURITY_LIBS_VERSION);
		printf("Plugin API:    %s\n", application::get_plugin_api_version().c_str());
		printf("Engine:        %d\n", FALCO_ENGINE_VERSION);

		printf("Driver:\n");
		printf("  API version:    %s\n", application::get_driver_api_version().c_str());
		printf("  Schema version: %s\n", application::get_driver_api_version().c_str());
		printf("  Default driver: %s\n", DRIVER_VERSION);

		return run_result::exit();
	}
	
	if(m_options.print_version_info_json)
	{
		nlohmann::json version_info;

		version_info["falco_version"] = FALCO_VERSION;
		version_info["libs_version"] = FALCOSECURITY_LIBS_VERSION;
		version_info["plugin_api_version"] = application::get_plugin_api_version();
		version_info["driver_api_version"] = application::get_driver_api_version();
		version_info["driver_schema_version"] = application::get_driver_schema_version();
		version_info["default_driver_version"] = DRIVER_VERSION;
		version_info["engine_version"] = std::to_string(FALCO_ENGINE_VERSION);

		printf("%s\n", version_info.dump().c_str());

		return run_result::exit();
	}

	return run_result::ok();
}
