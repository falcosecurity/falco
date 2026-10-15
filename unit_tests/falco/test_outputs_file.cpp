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
#include <falco/outputs_file.h>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

namespace {

// Lets the test point the output at another file, as a reopen after a config
// change or a SIGUSR1 would.
class test_output_file : public falco::outputs::output_file {
public:
	void set_filename(const std::string& filename) { m_oc.options["filename"] = filename; }
};

std::string read_file(const std::string& path) {
	std::ifstream in(path);
	std::stringstream ss;
	ss << in.rdbuf();
	return ss.str();
}

}  // namespace

// Writing to /dev/full fails with ENOSPC, like a full filesystem.
TEST(OutputsFile, failed_write_with_keep_alive_is_reported_and_recovers) {
	falco::outputs::config oc;
	oc.name = "file";
	oc.options["filename"] = "/dev/full";
	oc.options["keep_alive"] = "true";

	test_output_file out;
	falco::outputs::abstract_output& output = out;
	std::string err;
	ASSERT_TRUE(output.init(oc, false, "host", false, err));

	falco::outputs::message msg;
	msg.msg = "alert";

	EXPECT_THROW(output.output(&msg), falco_exception);
	// still reported, not silently dropped by a stream left in a fail state
	EXPECT_THROW(output.output(&msg), falco_exception);

	// once writes can succeed again, they do
	std::string path = ::testing::TempDir() + "falco_test_outputs_file.txt";
	std::remove(path.c_str());
	out.set_filename(path);
	EXPECT_NO_THROW(output.output(&msg));
	output.cleanup();
	EXPECT_EQ(read_file(path), "alert\n");
	std::remove(path.c_str());
}
