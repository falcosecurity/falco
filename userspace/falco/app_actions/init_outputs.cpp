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

#include "init_outputs.h"

namespace falco {
namespace app {

act_init_outputs::act_init_outputs(application &app)
	: init_action(app), m_name("init outputs"),
	  m_prerequsites({"load config", "init falco engine"})
{
}

act_init_outputs::~act_init_outputs()
{
}

const std::string &act_init_outputs::name()
{
	return m_name;
}

const std::list<std::string> &act_init_outputs::prerequsites()
{
	return m_prerequsites;
}

runnable_action::run_result act_init_outputs::run()
{
	run_result ret = {true, "", true};

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

	state().outputs->init(state().engine,
				    state().config->m_json_output,
				    state().config->m_json_include_output_property,
				    state().config->m_json_include_tags_property,
				    state().config->m_output_timeout,
				    state().config->m_notifications_rate, state().config->m_notifications_max_burst,
				    state().config->m_buffered_outputs,
				    state().config->m_time_format_iso_8601,
				    hostname);

	for(auto output : state().config->m_outputs)
	{
		state().outputs->add_output(output);
	}

	return ret;
}

}; // namespace application
}; // namespace falco

