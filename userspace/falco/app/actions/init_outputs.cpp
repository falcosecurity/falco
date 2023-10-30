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

#include <stdlib.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "actions.h"

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::init_outputs(falco::app::state& s)
{
	if (s.config->m_outputs.empty())
	{
		return run_result::fatal("No output configured, please make sure at least one output is configured and enabled.");
	}

	// read hostname
	std::string hostname;
	char* env_hostname = getenv("FALCO_HOSTNAME");
	// todo(leogr): keep FALCO_GRPC_HOSTNAME for backward compatibility. Shall we deprecate it?
	if(env_hostname || (env_hostname = getenv("FALCO_GRPC_HOSTNAME")))
	{
		hostname = env_hostname;
		falco_logger::log(falco_logger::level::INFO, "Hostname value has been overridden via environment variable to: " + hostname + "\n");
	}
	else
	{
		char c_hostname[256];
		int err = gethostname(c_hostname, 256);
		if(err != 0)
		{
			return run_result::fatal("Failed to get hostname");
		}
		hostname = c_hostname;
	}

	if (s.options.dry_run)
	{
		falco_logger::log(falco_logger::level::DEBUG, "Skipping outputs initialization in dry-run\n");
		return run_result::ok();
	}

	s.outputs.reset(new falco_outputs(
		s.engine,
		s.config->m_outputs,
		s.config->m_json_output,
		s.config->m_json_include_output_property,
		s.config->m_json_include_tags_property,
		s.config->m_output_timeout,
		s.config->m_buffered_outputs,
		s.config->m_outputs_queue_capacity,
		s.config->m_time_format_iso_8601,
		hostname));

	return run_result::ok();
}
