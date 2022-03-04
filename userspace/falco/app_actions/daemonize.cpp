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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "daemonize.h"

namespace falco {
namespace app {

act_daemonize::act_daemonize(application &app)
	: run_action(app), m_name("daemonize"), m_daemonized(false)
{
}

act_daemonize::~act_daemonize()
{
}

const std::string &act_daemonize::name()
{
	return m_name;
}

const std::list<std::string> &act_daemonize::prerequsites()
{
	return m_prerequsites;
}

runnable_action::run_result act_daemonize::run()
{
	run_result ret = {true, "", true};

	// If daemonizing, do it here so any init errors will
	// be returned in the foreground process.
	if (options().daemon && !m_daemonized) {
		pid_t pid, sid;

		pid = fork();
		if (pid < 0) {
			// error
			ret.success = false;
			ret.errstr = "Could not fork.";
			ret.proceed = false;
			return ret;
		} else if (pid > 0) {
			// parent. Write child pid to pidfile and exit
			std::ofstream pidfile;
			pidfile.open(options().pidfilename);

			if (!pidfile.good())
			{
				ret.success = false;
				ret.errstr = string("Could not write pid to pid file ") + options().pidfilename + ".";
				ret.proceed = false;
				return ret;
			}
			pidfile << pid;
			pidfile.close();
			return ret;
		}
		// if here, child.

		// Become own process group.
		sid = setsid();
		if (sid < 0) {
			ret.success = false;
			ret.errstr = string("Could not set session id.");
			ret.proceed = false;
			return ret;
		}

		// Set umask so no files are world anything or group writable.
		umask(027);

		// Change working directory to '/'
		if ((chdir("/")) < 0) {
			ret.success = false;
			ret.errstr = string("Could not change working directory to '/'.");
			ret.proceed = false;
			return ret;
		}

		// Close stdin, stdout, stderr and reopen to /dev/null
		close(0);
		close(1);
		close(2);
		open("/dev/null", O_RDONLY);
		open("/dev/null", O_RDWR);
		open("/dev/null", O_RDWR);

		m_daemonized = true;
	}

	return ret;
}

}; // namespace application
}; // namespace falco

