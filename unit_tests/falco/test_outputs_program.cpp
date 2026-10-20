// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <gtest/gtest.h>
#include <falco/outputs_program.h>

#include <chrono>
#include <csignal>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>

namespace {

// Lets the test point the output at another program, as a reopen after a
// config change would.
class test_output_program : public falco::outputs::output_program {
public:
	void set_program(const std::string& program) { m_oc.options["program"] = program; }
};

std::string read_file(const std::string& path) {
	std::ifstream in(path);
	std::stringstream ss;
	ss << in.rdbuf();
	return ss.str();
}

bool wait_for_file(const std::string& path) {
	for(int i = 0; i < 1000; i++) {
		if(access(path.c_str(), F_OK) == 0) {
			return true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	return false;
}

// A program that exited is waited for without blocking, so it may still be
// exiting when the next alert comes. Retry until the alert is delivered.
bool output_until_delivered(falco::outputs::abstract_output& output,
                            const falco::outputs::message& msg,
                            const std::string& path) {
	for(int i = 0; i < 1000; i++) {
		output.output(&msg);
		output.cleanup();
		if(read_file(path) == msg.msg + "\n") {
			return true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	return false;
}

}  // namespace

// The program closes its input and exits while Falco keeps the pipe open, like
// a program that crashed. The next write must neither kill Falco with SIGPIPE
// nor be lost silently.
TEST(OutputsProgram, failed_write_with_keep_alive_is_reported_and_recovers) {
	// Falco starts with the default SIGPIPE action, which terminates the process.
	std::signal(SIGPIPE, SIG_DFL);

	const std::string closed = ::testing::TempDir() + "falco_test_outputs_program_closed";
	const std::string path = ::testing::TempDir() + "falco_test_outputs_program.txt";
	std::remove(closed.c_str());
	std::remove(path.c_str());

	falco::outputs::config oc;
	oc.name = "program";
	// Once the file exists, the program has closed the only read end of the pipe.
	oc.options["program"] = "exec 0<&-; touch " + closed;
	oc.options["keep_alive"] = "true";

	test_output_program out;
	falco::outputs::abstract_output& output = out;
	std::string err;
	ASSERT_TRUE(output.init(oc, false, "host", false, err));

	output.reopen();
	ASSERT_TRUE(wait_for_file(closed));

	falco::outputs::message msg;
	msg.msg = "alert";
	EXPECT_THROW(output.output(&msg), falco_exception);

	// the next alert starts the program again
	out.set_program("cat > " + path);
	EXPECT_TRUE(output_until_delivered(output, msg, path));
	std::remove(closed.c_str());
	std::remove(path.c_str());
}

// The program closes its input but keeps running. Waiting for it after the
// failed write would block every output channel, so the write must fail right
// away, and the program must not be started again while it is still running.
TEST(OutputsProgram, failed_write_does_not_wait_for_running_program) {
	std::signal(SIGPIPE, SIG_DFL);

	const std::string started = ::testing::TempDir() + "falco_test_outputs_program_started";
	const std::string closed = ::testing::TempDir() + "falco_test_outputs_program_closed";
	const std::string release = ::testing::TempDir() + "falco_test_outputs_program_release";
	const std::string path = ::testing::TempDir() + "falco_test_outputs_program.txt";
	for(const auto& file : {started, closed, release, path}) {
		std::remove(file.c_str());
	}

	falco::outputs::config oc;
	oc.name = "program";
	// After closing its input, the program runs until released, for about 10 seconds at most.
	oc.options["program"] = "echo >> " + started + "; exec 0<&-; touch " + closed +
	                        "; n=0; while [ ! -e " + release +
	                        " ] && [ $n -lt 1000 ]; do sleep 0.01; n=$((n + 1)); done";
	oc.options["keep_alive"] = "true";

	test_output_program out;
	falco::outputs::abstract_output& output = out;
	std::string err;
	ASSERT_TRUE(output.init(oc, false, "host", false, err));

	output.reopen();
	ASSERT_TRUE(wait_for_file(closed));

	falco::outputs::message msg;
	msg.msg = "alert";
	const auto start = std::chrono::steady_clock::now();
	EXPECT_THROW(output.output(&msg), falco_exception);
	// the program is still running, so it is not started again
	EXPECT_NO_THROW(output.output(&msg));
	const auto elapsed = std::chrono::steady_clock::now() - start;
	EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 2000);
	EXPECT_EQ(read_file(started), "\n");

	// once it has exited, the next alert starts the program again
	std::ofstream(release).close();
	out.set_program("cat > " + path);
	EXPECT_TRUE(output_until_delivered(output, msg, path));
	for(const auto& file : {started, closed, release, path}) {
		std::remove(file.c_str());
	}
}

// Falco must not change how the program itself reacts to SIGPIPE: an ignored
// signal would be inherited across exec, a caught one is reset to the default.
TEST(OutputsProgram, program_keeps_default_sigpipe_action) {
	std::signal(SIGPIPE, SIG_DFL);

	const std::string path = ::testing::TempDir() + "falco_test_outputs_program_sigpipe.txt";
	std::remove(path.c_str());

	falco::outputs::config oc;
	oc.name = "program";
	// With the default action, the shell terminates before writing the file.
	oc.options["program"] = "kill -PIPE $$; echo survived > " + path;
	oc.options["keep_alive"] = "false";

	test_output_program out;
	falco::outputs::abstract_output& output = out;
	std::string err;
	ASSERT_TRUE(output.init(oc, false, "host", false, err));

	falco::outputs::message msg;
	msg.msg = "alert";
	try {
		output.output(&msg);
	} catch(const falco_exception&) {
		// the program may be gone before the alert is written
	}
	output.cleanup();
	EXPECT_EQ(read_file(path), "");
	std::remove(path.c_str());
}
