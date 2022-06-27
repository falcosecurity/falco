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

#include <stdio.h>
#include <string>

#include <iostream>

#include "application.h"
#include "logger.h"
#include "banned.h" // This raises a compilation error when certain functions are used

static void display_fatal_err(const string &&msg)
{
	/**
	 * If stderr logging is not enabled, also log to stderr. When
	 * daemonized this will simply write to /dev/null.
	 */
	if (! falco_logger::log_stderr)
	{
		std::cerr << msg;
	}

	falco_logger::log(LOG_ERR, std::move(msg));
}

//
// ARGUMENT PARSING AND PROGRAM SETUP
//
int falco_init(int argc, char **argv, bool &restart)
{
	falco::app::application app;
	restart = false;

	std::string errstr;
	bool successful = app.init(argc, argv, errstr);

	if(!successful)
	{
		fprintf(stderr, "Runtime error: %s. Exiting.\n", errstr.c_str());
		return EXIT_FAILURE;
	}

	try
	{
		bool success;
		std::string errstr;

		success = app.run(errstr, restart);

		if(!success)
		{
			fprintf(stderr, "Error: %s\n", errstr.c_str());
			return EXIT_FAILURE;
		}
	}
	catch(exception &e)
	{
		display_fatal_err("Runtime error: " + string(e.what()) + ". Exiting.\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

//
// MAIN
//
int main(int argc, char **argv)
{
	int rc;
	bool restart;

	// Generally falco exits when falco_init returns with the rc
	// returned by falco_init. However, when restart (set by
	// signal handlers, returned in application::run()) is true,
	// falco_init() is called again.
	while((rc = falco_init(argc, argv, restart)) == EXIT_SUCCESS && restart)
	{
	}

	return rc;
}
