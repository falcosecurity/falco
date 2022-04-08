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

using namespace falco::app;

application::run_result application::print_version()
{
	run_result ret;

	if(m_options.print_version_info)
	{
		printf("Falco version: %s\n", FALCO_VERSION);
		printf("Driver version: %s\n", DRIVER_VERSION);
		ret.proceed = false;
	}

	return ret;
}
