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

#include <falco_engine.h>

// Helper: capture stdout from list_fields() and return it as a string.
static std::string capture_list_fields(falco_engine& engine,
                                       const std::string& source,
                                       output_format fmt) {
	testing::internal::CaptureStdout();
	engine.list_fields(source, false, false, fmt);
	return testing::internal::GetCapturedStdout();
}

// Extract the section of the output that belongs to a given field class.
// Returns everything from "## Field Class: <name>" up to the next "## Field Class:" line.
static std::string extract_section(const std::string& output, const std::string& class_name) {
	const std::string header = "## Field Class: " + class_name + "\n";
	auto start = output.find(header);
	if(start == std::string::npos) {
		return "";
	}
	auto next = output.find("## Field Class:", start + header.size());
	return output.substr(start, next == std::string::npos ? std::string::npos : next - start);
}

class ListFields : public testing::Test {
protected:
	void SetUp() override {
		auto filter_factory =
		        std::make_shared<sinsp_filter_factory>(&m_inspector, m_filterchecks);
		auto formatter_factory =
		        std::make_shared<sinsp_evt_formatter_factory>(&m_inspector, m_filterchecks);
		m_engine.add_source("syscall", filter_factory, formatter_factory);
	}

	falco_engine m_engine;
	sinsp m_inspector;
	sinsp_filter_check_list m_filterchecks;
};

// evt.* is source-agnostic - its section must not carry an "Event Sources:" line.
TEST_F(ListFields, generic_evt_class_has_no_source_label) {
	auto output = capture_list_fields(m_engine, "", output_format::MARKDOWN);

	auto evt_section = extract_section(output, "evt");
	ASSERT_FALSE(evt_section.empty()) << "evt field class section not found in output";
	EXPECT_EQ(evt_section.find("Event Sources:"), std::string::npos)
	        << "evt section must not have an Event Sources line:\n"
	        << evt_section;
}

// fd.* is syscall-specific - its section must carry "Event Sources: syscall".
TEST_F(ListFields, syscall_specific_class_has_source_label) {
	auto output = capture_list_fields(m_engine, "", output_format::MARKDOWN);

	auto fd_section = extract_section(output, "fd");
	ASSERT_FALSE(fd_section.empty()) << "fd field class section not found in output";
	EXPECT_NE(fd_section.find("Event Sources: syscall"), std::string::npos)
	        << "fd section must have Event Sources: syscall:\n"
	        << fd_section;
}
