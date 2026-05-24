#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <engine/formats.h>

#include "../test_falco_engine.h"

namespace {

static void init_test_event(sinsp_evt &evt, sinsp &inspector, scap_evt &scap_evt) {
	scap_evt.ts = 1000000000;
	scap_evt.tid = 1;
	scap_evt.len = sizeof(scap_evt);
	scap_evt.type = PPME_GENERIC_E;
	scap_evt.nparams = 0;
	evt.init_from_raw(&inspector, &scap_evt, 0);
}

}  // namespace

TEST(FalcoFormats, escape_text_output_controls) {
	ASSERT_EQ(falco_formats::escape_text_output(""), "");
	ASSERT_EQ(falco_formats::escape_text_output("\n"), "\\n");
	ASSERT_EQ(falco_formats::escape_text_output("\r"), "\\r");
	ASSERT_EQ(falco_formats::escape_text_output("\t"), "\\t");
	ASSERT_EQ(falco_formats::escape_text_output(std::string(1, '\x1b')), "\\u001b");
	ASSERT_EQ(falco_formats::escape_text_output(std::string("a\0b", 3)), "a\\u0000b");
	ASSERT_EQ(falco_formats::escape_text_output(std::string(1, '\x7f')), "\\u007f");
	ASSERT_EQ(falco_formats::escape_text_output(std::string(1, '\x1f')), "\\u001f");
}

TEST(FalcoFormats, escape_text_output_keeps_printable_bytes) {
	ASSERT_EQ(falco_formats::escape_text_output(" "), " ");

	const std::string utf8 = std::string("\xc3\xa9", 2);
	ASSERT_EQ(falco_formats::escape_text_output(utf8), utf8);
}

TEST_F(test_falco_engine, format_event_escapes_normal_output) {
	scap_evt raw_evt = {};
	sinsp_evt evt;
	init_test_event(evt, m_inspector, raw_evt);

	falco_formats formats(m_engine, true, false, false, false, false);
	std::set<std::string> tags;
	extra_output_field_t extra_fields;
	const std::string output = formats.format_event(&evt,
	                                                "test rule",
	                                                falco_common::syscall_source,
	                                                "Warning",
	                                                "line\nnext\tend",
	                                                tags,
	                                                "host",
	                                                extra_fields);

	ASSERT_NE(output.find(": Warning line\\nnext\\tend"), std::string::npos);
	ASSERT_EQ(output.find("line\nnext"), std::string::npos);
}

TEST_F(test_falco_engine, format_event_json_output_is_not_double_escaped) {
	m_formatter_factory->set_output_format(sinsp_evt_formatter::OF_JSON);

	scap_evt raw_evt = {};
	sinsp_evt evt;
	init_test_event(evt, m_inspector, raw_evt);

	falco_formats formats(m_engine, true, false, true, false, false);
	std::set<std::string> tags;
	extra_output_field_t extra_fields;
	const std::string output = formats.format_event(&evt,
	                                                "test rule",
	                                                falco_common::syscall_source,
	                                                "Warning",
	                                                "line\nnext",
	                                                tags,
	                                                "host",
	                                                extra_fields);

	const auto event = nlohmann::json::parse(output);
	ASSERT_EQ(event.at("message").get<std::string>(), "line\nnext");
	ASSERT_NE(event.at("output").get<std::string>().find("line\nnext"), std::string::npos);
	ASSERT_EQ(output.find(R"(line\\nnext)"), std::string::npos);
}
