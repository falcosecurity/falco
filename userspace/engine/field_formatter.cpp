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

#include "field_formatter.h"
#include "formats.h"

using namespace falco;

// Factory method
std::unique_ptr<FieldFormatter> FieldFormatter::create(output_format format, bool verbose) {
	switch(format) {
	case output_format::JSON:
		return std::make_unique<JsonFieldFormatter>(verbose);
	case output_format::MARKDOWN:
		return std::make_unique<MarkdownFieldFormatter>(verbose);
	case output_format::TEXT:
	default:
		return std::make_unique<TextFieldFormatter>(verbose);
	}
}

// ============================================================================
// TextFieldFormatter implementation
// ============================================================================

TextFieldFormatter::TextFieldFormatter(bool verbose): m_verbose(verbose) {}

void TextFieldFormatter::begin() {
	// Nothing to do for text format
}

void TextFieldFormatter::print_fieldclass(
        const sinsp_filter_factory::filter_fieldclass_info& fld_class,
        const std::set<std::string>& event_sources) {
	printf("%s\n", fld_class.as_string(m_verbose, event_sources).c_str());
}

void TextFieldFormatter::print_field_name(const std::string& name) {
	printf("%s\n", name.c_str());
}

void TextFieldFormatter::end() {
	// Nothing to do for text format
}

// ============================================================================
// MarkdownFieldFormatter implementation
// ============================================================================

MarkdownFieldFormatter::MarkdownFieldFormatter(bool verbose): m_verbose(verbose) {}

void MarkdownFieldFormatter::begin() {
	// Nothing to do for markdown format
}

void MarkdownFieldFormatter::print_fieldclass(
        const sinsp_filter_factory::filter_fieldclass_info& fld_class,
        const std::set<std::string>& event_sources) {
	printf("%s\n", fld_class.as_markdown(event_sources).c_str());
}

void MarkdownFieldFormatter::print_field_name(const std::string& name) {
	printf("%s\n", name.c_str());
}

void MarkdownFieldFormatter::end() {
	// Nothing to do for markdown format
}

// ============================================================================
// JsonFieldFormatter implementation
// ============================================================================

JsonFieldFormatter::JsonFieldFormatter(bool verbose): m_verbose(verbose) {}

void JsonFieldFormatter::begin() {
	m_fieldclasses_array = nlohmann::json::array();
	m_fieldnames_array = nlohmann::json::array();
	m_has_fieldclasses = false;
	m_has_fieldnames = false;
}

void JsonFieldFormatter::print_fieldclass(
        const sinsp_filter_factory::filter_fieldclass_info& fld_class,
        const std::set<std::string>& event_sources) {
	std::string json_str = fld_class.as_json(event_sources);
	if(!json_str.empty()) {
		m_fieldclasses_array.push_back(nlohmann::json::parse(json_str));
		m_has_fieldclasses = true;
	}
}

void JsonFieldFormatter::print_field_name(const std::string& name) {
	m_fieldnames_array.push_back(name);
	m_has_fieldnames = true;
}

void JsonFieldFormatter::end() {
	nlohmann::json root;

	if(m_has_fieldclasses) {
		root["fieldclasses"] = m_fieldclasses_array;
		printf("%s\n", root.dump(2).c_str());
	} else if(m_has_fieldnames) {
		root["fieldnames"] = m_fieldnames_array;
		printf("%s\n", root.dump(2).c_str());
	}
}
