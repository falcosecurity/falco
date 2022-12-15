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
		printf("Plugin API:    %s\n", s->get_plugin_api_version());
		printf("Engine:        %d\n", FALCO_ENGINE_VERSION);

		// todo(leogr): move string conversion to scap
		auto driver_api_version = s->get_scap_api_version();
		unsigned long driver_api_major = PPM_API_VERSION_MAJOR(driver_api_version);
		unsigned long driver_api_minor = PPM_API_VERSION_MINOR(driver_api_version);
		unsigned long driver_api_patch = PPM_API_VERSION_PATCH(driver_api_version);
		auto driver_schema_version = s->get_scap_schema_version();
		unsigned long driver_schema_major = PPM_API_VERSION_MAJOR(driver_schema_version);
		unsigned long driver_schema_minor = PPM_API_VERSION_MINOR(driver_schema_version);
		unsigned long driver_schema_patch = PPM_API_VERSION_PATCH(driver_schema_version);
		printf("Driver:\n");
		printf("  API version:    %lu.%lu.%lu\n", driver_api_major, driver_api_minor, driver_api_patch);
		printf("  Schema version: %lu.%lu.%lu\n", driver_schema_major, driver_schema_minor, driver_schema_patch);
		printf("  Default driver: %s\n", DRIVER_VERSION);

		return run_result::exit();
	}
	return run_result::ok();
}
