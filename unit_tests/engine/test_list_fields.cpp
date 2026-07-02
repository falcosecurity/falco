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

#include <nlohmann/json.hpp>

#include <falco_engine.h>

// Helper: capture stdout from list_fields() and return it as a string.
static std::string capture_list_fields(const falco_engine& engine,
                                       const std::string& source,
                                       output_format fmt) {
	testing::internal::CaptureStdout();
	engine.list_fields(source, false, false, fmt);
	return testing::internal::GetCapturedStdout();
}

// In the markdown output a section header only carries the class name, and
// two classes are named `evt` (the generic one and the syscall-only one), so
// sections are located by header plus description.
static const std::string generic_evt_header =
        "## Field Class: evt\n\nThese fields can be used for all event types\n";
static const std::string syscall_evt_header =
        "## Field Class: evt\n\nEvent fields applicable to syscall events";
static const std::string fd_header = "## Field Class: fd\n";

// Extract the section of the markdown output that starts with the given
// header, up to the next "## Field Class:" header (or the end of the output).
static std::string extract_section(const std::string& output, const std::string& header) {
	auto start = output.find(header);
	if(start == std::string::npos) {
		return "";
	}
	auto next = output.find("## Field Class:", start + header.size());
	return output.substr(start, next == std::string::npos ? std::string::npos : next - start);
}

// Find a field class in the JSON output by name and description prefix.
// Returns a null JSON value if not found.
static nlohmann::json find_json_fieldclass(const nlohmann::json& output,
                                           const std::string& name,
                                           const std::string& desc_prefix) {
	for(const auto& fld_class : output.at("fieldclasses")) {
		if(fld_class.at("name") == name && fld_class.value("desc", "").rfind(desc_prefix, 0) == 0) {
			return fld_class;
		}
	}
	return nlohmann::json();
}

class ListFields : public testing::Test {
protected:
	void SetUp() override {
		auto filter_factory = std::make_shared<sinsp_filter_factory>(&m_inspector, m_filterchecks);
		auto formatter_factory =
		        std::make_shared<sinsp_evt_formatter_factory>(&m_inspector, m_filterchecks);
		m_engine.add_source("syscall", filter_factory, formatter_factory);
	}

	// The engine keeps the factories, which reference the inspector and the
	// filter check list: declare it last so that it is destroyed first.
	sinsp m_inspector;
	sinsp_filter_check_list m_filterchecks;
	falco_engine m_engine;
};

// The generic `evt` class applies to every event source: its section must
// not carry an "Event Sources:" line.
TEST_F(ListFields, generic_evt_class_has_no_source_label) {
	auto output = capture_list_fields(m_engine, "", output_format::MARKDOWN);

	auto section = extract_section(output, generic_evt_header);
	ASSERT_FALSE(section.empty()) << "generic evt field class section not found in output";
	EXPECT_EQ(section.find("Event Sources:"), std::string::npos)
	        << "generic evt section must not have an Event Sources line:\n"
	        << section;
}

// The syscall-only `evt` class shares the name but is source-specific: it
// must keep its label (the generic flag drives the behavior, not the name).
TEST_F(ListFields, syscall_evt_class_has_source_label) {
	auto output = capture_list_fields(m_engine, "", output_format::MARKDOWN);

	auto section = extract_section(output, syscall_evt_header);
	ASSERT_FALSE(section.empty()) << "syscall evt field class section not found in output";
	EXPECT_NE(section.find("Event Sources: syscall"), std::string::npos)
	        << "syscall evt section must have Event Sources: syscall:\n"
	        << section;
}

// fd.* is syscall-specific: its section must carry "Event Sources: syscall".
TEST_F(ListFields, syscall_specific_class_has_source_label) {
	auto output = capture_list_fields(m_engine, "", output_format::MARKDOWN);

	auto section = extract_section(output, fd_header);
	ASSERT_FALSE(section.empty()) << "fd field class section not found in output";
	EXPECT_NE(section.find("Event Sources: syscall"), std::string::npos)
	        << "fd section must have Event Sources: syscall:\n"
	        << section;
}

// Same expectations on the JSON output: the generic `evt` class has no
// `event_sources` key, while source-specific classes list `syscall`.
TEST_F(ListFields, json_output_labels_only_source_specific_classes) {
	auto output = nlohmann::json::parse(capture_list_fields(m_engine, "", output_format::JSON));
	auto syscall_only = nlohmann::json::array({"syscall"});

	auto generic_evt =
	        find_json_fieldclass(output, "evt", "These fields can be used for all event types");
	ASSERT_FALSE(generic_evt.is_null()) << "generic evt field class not found in output";
	EXPECT_FALSE(generic_evt.contains("event_sources")) << generic_evt.dump(2);

	auto syscall_evt =
	        find_json_fieldclass(output, "evt", "Event fields applicable to syscall events");
	ASSERT_FALSE(syscall_evt.is_null()) << "syscall evt field class not found in output";
	ASSERT_TRUE(syscall_evt.contains("event_sources")) << syscall_evt.dump(2);
	EXPECT_EQ(syscall_evt["event_sources"], syscall_only);

	auto fd = find_json_fieldclass(output, "fd", "");
	ASSERT_FALSE(fd.is_null()) << "fd field class not found in output";
	ASSERT_TRUE(fd.contains("event_sources")) << fd.dump(2);
	EXPECT_EQ(fd["event_sources"], syscall_only);
}
