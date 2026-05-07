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

#ifndef _WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include "compat.h"
#endif

#include "actions.h"

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::pidfile(const falco::app::state& state) {
	if(state.options.dry_run) {
		falco_logger::log(falco_logger::level::DEBUG, "Skipping pidfile creation in dry-run\n");
		return run_result::ok();
	}

	if(state.options.pidfilename.empty()) {
		return run_result::ok();
	}

#ifndef _WIN32
	// O_NOFOLLOW makes open() fail with ELOOP if the path is a symlink, so an
	// unprivileged user who can write to the pidfile's directory cannot
	// pre-place a symlink and trick a root-running Falco into clobbering an
	// arbitrary file with the PID.
	int fd = ::open(state.options.pidfilename.c_str(),
	                O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
	                0644);
	if(fd == -1) {
		char errbuf[256];
		const char* errstr = falco_strerror_r(errno, errbuf, sizeof(errbuf));
		falco_logger::log(falco_logger::level::ERR,
		                  "Could not write pid to pidfile " + state.options.pidfilename +
		                          " (error: " + errstr + "). Exiting.\n");
		exit(-1);
	}

	if(dprintf(fd, "%lld\n", (long long)getpid()) < 0) {
		char errbuf[256];
		const char* errstr = falco_strerror_r(errno, errbuf, sizeof(errbuf));
		falco_logger::log(falco_logger::level::ERR,
		                  "Could not write pid to pidfile " + state.options.pidfilename +
		                          " (error: " + errstr + "). Exiting.\n");
		::close(fd);
		exit(-1);
	}

	::close(fd);
#else
	int64_t self_pid = getpid();

	std::ofstream stream;
	stream.open(state.options.pidfilename);

	if(!stream.good()) {
		falco_logger::log(
		        falco_logger::level::ERR,
		        "Could not write pid to pidfile " + state.options.pidfilename + ". Exiting.\n");
		exit(-1);
	}
	stream << self_pid;
	stream.close();
#endif

	return run_result::ok();
}
