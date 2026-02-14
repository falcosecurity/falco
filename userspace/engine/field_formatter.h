// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#pragma once

#include <string>
#include <set>
#include <memory>
#include <nlohmann/json.hpp>

#include <libsinsp/sinsp.h>

enum class output_format;

namespace falco {

// Abstract formatter interface for field listing
class FieldFormatter {
public:
	virtual ~FieldFormatter() = default;

	// Initialize formatter
	virtual void begin() = 0;

	// Print a field class with its event sources
	virtual void print_fieldclass(const sinsp_filter_factory::filter_fieldclass_info& fld_class,
	                              const std::set<std::string>& event_sources) = 0;

	// Print a single field name (for names_only mode)
	virtual void print_field_name(const std::string& name) = 0;

	// Finalize and output
	virtual void end() = 0;

	// Factory method
	static std::unique_ptr<FieldFormatter> create(output_format format, bool verbose);
};

// Text formatter (default)
class TextFieldFormatter : public FieldFormatter {
public:
	explicit TextFieldFormatter(bool verbose);

	void begin() override;
	void print_fieldclass(const sinsp_filter_factory::filter_fieldclass_info& fld_class,
	                     const std::set<std::string>& event_sources) override;
	void print_field_name(const std::string& name) override;
	void end() override;

private:
	bool m_verbose;
};

// Markdown formatter
class MarkdownFieldFormatter : public FieldFormatter {
public:
	explicit MarkdownFieldFormatter(bool verbose);

	void begin() override;
	void print_fieldclass(const sinsp_filter_factory::filter_fieldclass_info& fld_class,
	                     const std::set<std::string>& event_sources) override;
	void print_field_name(const std::string& name) override;
	void end() override;

private:
	bool m_verbose;
};

// JSON formatter
class JsonFieldFormatter : public FieldFormatter {
public:
	explicit JsonFieldFormatter(bool verbose);

	void begin() override;
	void print_fieldclass(const sinsp_filter_factory::filter_fieldclass_info& fld_class,
	                     const std::set<std::string>& event_sources) override;
	void print_field_name(const std::string& name) override;
	void end() override;

private:
	bool m_verbose;
	nlohmann::json m_fieldclasses_array;
	nlohmann::json m_fieldnames_array;
	bool m_has_fieldclasses{false};
	bool m_has_fieldnames{false};
};

}  // namespace falco
