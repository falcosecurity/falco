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

#include "config_falco.h"
#include "actions.h"

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::print_generated_gvisor_config(falco::app::state& s)
{
	if(!s.options.gvisor_generate_config_with_socket.empty())
	{
		sinsp i;
		std::string gvisor_config = i.generate_gvisor_config(s.options.gvisor_generate_config_with_socket);
		printf("%s\n", gvisor_config.c_str());
		return run_result::exit();
	}
	return run_result::ok();
}
