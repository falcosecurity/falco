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

#include <stdio.h>
#include <string>

#include <iostream>

#include "app/app.h"
#include "logger.h"

static void display_fatal_err(const std::string &&msg)
{
	/**
	 * If stderr logging is not enabled, also log to stderr.
	 */
	if (! falco_logger::log_stderr)
	{
		std::cerr << msg;
	}

	falco_logger::log(falco_logger::level::ERR, std::move(msg));
}

//
// ARGUMENT PARSING AND PROGRAM SETUP
//
int falco_run(int argc, char **argv, bool &restart)
{
	restart = false;
	std::string errstr;
	try
	{
		if (!falco::app::run(argc, argv, restart, errstr))
		{
			fprintf(stderr, "Error: %s\n", errstr.c_str());
			return EXIT_FAILURE;
		}
	}
	catch(std::exception &e)
	{
		display_fatal_err("Runtime error: " + std::string(e.what()) + ". Exiting.\n");
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

	// Generally falco exits when falco_run returns with the rc
	// returned by falco_run. However, when restart (set by
	// signal handlers, returned in application::run()) is true,
	// falco_run() is called again.
	while((rc = falco_run(argc, argv, restart)) == EXIT_SUCCESS && restart)
	{
	}

	return rc;
}
