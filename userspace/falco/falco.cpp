/*
Copyright (C) 2020 The Falco Authors.

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

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <set>
#include <list>
#include <vector>
#include <algorithm>
#include <string>
#include <chrono>
#include <functional>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>

#include <sinsp.h>
#include <filter.h>
#include <eventformatter.h>
#include <plugin.h>

#include "application.h"
#include "logger.h"
#include "utils.h"
#include "fields_info.h"

#include "event_drops.h"
#include "falco_engine.h"
#include "config_falco.h"
#ifndef MINIMAL_BUILD
#include "webserver.h"
#endif
#include "banned.h" // This raises a compilation error when certain functions are used

static std::string syscall_source = "syscall";
static std::string k8s_audit_source = "k8s_audit";

static void display_fatal_err(const string &msg)
{
	falco_logger::log(LOG_ERR, msg);

	/**
	 * If stderr logging is not enabled, also log to stderr. When
	 * daemonized this will simply write to /dev/null.
	 */
	if (! falco_logger::log_stderr)
	{
		std::cerr << msg;
	}
}


//
// ARGUMENT PARSING AND PROGRAM SETUP
//
int falco_init(falco::app::application &app, int argc, char **argv)
{
	int result = EXIT_SUCCESS;

	std::string errstr;
	bool successful = app.init(argc, argv, errstr);

	if(!successful)
	{
		fprintf(stderr, "Runtime error: %s. Exiting.\n", errstr.c_str());
		return EXIT_FAILURE;
	}

	try
	{
		app.run();
	}
	catch(exception &e)
	{
		display_fatal_err("Runtime error: " + string(e.what()) + ". Exiting.\n");

		result = EXIT_FAILURE;
	}

	return result;
}

//
// MAIN
//
int main(int argc, char **argv)
{
	int rc;
	falco::app::application &app = falco::app::application::get();

	// m_restart will cause the falco loop to exit, but we
	// should reload everything and start over.
	while((rc = falco_init(app, argc, argv)) == EXIT_SUCCESS && app.state().restart)
	{
		app.state().restart = false;
	}

	return rc;
}
