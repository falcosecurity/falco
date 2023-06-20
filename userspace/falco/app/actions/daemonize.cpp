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

static bool s_daemonized = false;

falco::app::run_result falco::app::actions::daemonize(falco::app::state& s)
{
#ifdef __linux__
	if (s.options.dry_run)
	{
		falco_logger::log(LOG_DEBUG, "Skipping daemonizing in dry-run\n");
		return run_result::ok();
	}

	// If daemonizing, do it here so any init errors will
	// be returned in the foreground process.
	if (s.options.daemon && !s_daemonized) {
		pid_t pid, sid;

		pid = fork();
		if (pid < 0) {
			// error
			return run_result::fatal("Could not fork");
		} else if (pid > 0) {
			// parent. Write child pid to pidfile and exit
			std::ofstream pidfile;
			pidfile.open(s.options.pidfilename);

			if (!pidfile.good())
			{
				falco_logger::log(LOG_ERR, "Could not write pid to pid file " + s.options.pidfilename + ". Exiting.\n");
				exit(-1);
			}
			pidfile << pid;
			pidfile.close();
			exit(0);
		}
		// if here, child.

		// Become own process group.
		sid = setsid();
		if (sid < 0) {
			return run_result::fatal("Could not set session id");
		}

		// Set umask so no files are world anything or group writable.
		umask(027);

		// Change working directory to '/'
		if ((chdir("/")) < 0) {
			return run_result::fatal("Could not change working directory to '/'");
		}

		// Close stdin, stdout, stderr and reopen to /dev/null
		close(0);
		close(1);
		close(2);
		open("/dev/null", O_RDONLY);
		open("/dev/null", O_RDWR);
		open("/dev/null", O_RDWR);

		s_daemonized = true;
	}
#endif // __linux__

	return run_result::ok();
}
