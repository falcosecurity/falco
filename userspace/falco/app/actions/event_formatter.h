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

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <nlohmann/json.hpp>

#include "../../output_format.h"

struct ppm_param_info;
struct ppm_event_info;

namespace falco {
namespace app {
namespace actions {

struct event_entry {
	bool is_enter;
	bool available;
	std::string name;
	const ppm_event_info* info;
};

// Abstract formatter interface
class EventFormatter {
public:
	virtual ~EventFormatter() = default;

	// Initialize formatter with schema version
	virtual void begin(const std::string& schema_version) = 0;

	// Print category header
	virtual void begin_category(const std::string& category) = 0;

	// Print a single event
	virtual void print_event(const event_entry& e) = 0;

	// End category
	virtual void end_category() = 0;

	// Finalize and output
	virtual void end() = 0;

	// Factory method
	static std::unique_ptr<EventFormatter> create(output_format format);
};

// Text formatter (default)
class TextFormatter : public EventFormatter {
public:
	void begin(const std::string& schema_version) override;
	void begin_category(const std::string& category) override;
	void print_event(const event_entry& e) override;
	void end_category() override;
	void end() override;

private:
	void print_param(const struct ppm_param_info* param);
};

// Markdown formatter
class MarkdownFormatter : public EventFormatter {
public:
	void begin(const std::string& schema_version) override;
	void begin_category(const std::string& category) override;
	void print_event(const event_entry& e) override;
	void end_category() override;
	void end() override;

private:
	void print_param(const struct ppm_param_info* param);
	bool m_first_event_in_category{true};
};

// JSON formatter
class JsonFormatter : public EventFormatter {
public:
	void begin(const std::string& schema_version) override;
	void begin_category(const std::string& category) override;
	void print_event(const event_entry& e) override;
	void end_category() override;
	void end() override;

private:
	nlohmann::json m_root;
	nlohmann::json m_current_category;
	std::string m_current_category_name;

	nlohmann::json event_to_json(const event_entry& e);
};

}  // namespace actions
}  // namespace app
}  // namespace falco
