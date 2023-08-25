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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "actions.h"

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::pidfile(falco::app::state& s)
{
	if (s.options.dry_run)
	{
		falco_logger::log(LOG_DEBUG, "Skipping pidfile creation in dry-run\n");
		return run_result::ok();
	}

	if (!s.options.pidfilename.empty())
	{
		int64_t self_pid = getpid();

		std::ofstream pidfile;
		pidfile.open(s.options.pidfilename);

		if (!pidfile.good())
		{
			falco_logger::log(LOG_ERR, "Could not write pid to pidfile " + s.options.pidfilename + ". Exiting.\n");
			exit(-1);
		}
		pidfile << self_pid;
		pidfile.close();

	}

	return run_result::ok();
}
