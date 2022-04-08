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

#include <stdlib.h>
#include <unistd.h>

#include "application.h"

using namespace falco::app;

application::run_result application::init_outputs()
{
	run_result ret;

	// read hostname
	std::string hostname;
	if(char* env_hostname = getenv("FALCO_GRPC_HOSTNAME"))
	{
		hostname = env_hostname;
	}
	else
	{
		char c_hostname[256];
		int err = gethostname(c_hostname, 256);
		if(err != 0)
		{
			ret.success = false;
			ret.errstr = "Failed to get hostname";
			ret.proceed = false;
		}
		hostname = c_hostname;
	}

	m_state->outputs->init(m_state->engine,
			      m_state->config->m_json_output,
			      m_state->config->m_json_include_output_property,
			      m_state->config->m_json_include_tags_property,
			      m_state->config->m_output_timeout,
			      m_state->config->m_notifications_rate, m_state->config->m_notifications_max_burst,
			      m_state->config->m_buffered_outputs,
			      m_state->config->m_time_format_iso_8601,
			      hostname);

	for(auto output : m_state->config->m_outputs)
	{
		m_state->outputs->add_output(output);
	}

	return ret;
}
