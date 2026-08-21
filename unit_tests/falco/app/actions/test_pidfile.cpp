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

#include "app_action_helpers.h"

#include <filesystem>
#include <fstream>
#include <string>

#ifndef _WIN32
#include <unistd.h>
#else
#include <process.h>
#define getpid _getpid
#endif

TEST(ActionPidfile, empty_filename_is_noop) {
	falco::app::state s;
	s.options.pidfilename = "";
	EXPECT_ACTION_OK(falco::app::actions::pidfile(s));
}

TEST(ActionPidfile, dry_run_does_not_create_file) {
	auto path = std::filesystem::temp_directory_path() / "falco_test_dry_run.pid";
	std::filesystem::remove(path);

	falco::app::state s;
	s.options.dry_run = true;
	s.options.pidfilename = path.string();
	EXPECT_ACTION_OK(falco::app::actions::pidfile(s));
	EXPECT_FALSE(std::filesystem::exists(path));
}

TEST(ActionPidfile, writes_pid_to_file) {
	auto path = std::filesystem::temp_directory_path() / "falco_test_pidfile.pid";

	// Pre-fill the file with longer content to check it is fully replaced.
	{
		std::ofstream prefill(path.string());
		prefill << "999999999999999999\n";
	}

	falco::app::state s;
	s.options.pidfilename = path.string();
	EXPECT_ACTION_OK(falco::app::actions::pidfile(s));

	std::ifstream in(path.string());
	std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	EXPECT_EQ(content, std::to_string(getpid()) + "\n");

	std::filesystem::remove(path);
}
