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

#include "event_formatter.h"

#include <libsinsp/sinsp.h>
#include <libsinsp/event.h>

using namespace falco::app::actions;

static bool is_flag_type(ppm_param_type type) {
	return (type == PT_FLAGS8 || type == PT_FLAGS16 || type == PT_FLAGS32 ||
	        type == PT_ENUMFLAGS8 || type == PT_ENUMFLAGS16 || type == PT_ENUMFLAGS32);
}

// Factory method
std::unique_ptr<EventFormatter> EventFormatter::create(output_format format) {
	switch(format) {
	case output_format::JSON:
		return std::make_unique<JsonFormatter>();
	case output_format::MARKDOWN:
		return std::make_unique<MarkdownFormatter>();
	case output_format::TEXT:
	default:
		return std::make_unique<TextFormatter>();
	}
}

// ============================================================================
// TextFormatter implementation
// ============================================================================

void TextFormatter::begin(const std::string& schema_version) {
	printf("The events below are valid for Falco *Schema Version*: %s\n", schema_version.c_str());
}

void TextFormatter::begin_category(const std::string& category) {
	printf("## %s\n\n", category.c_str());
}

void TextFormatter::print_event(const event_entry& e) {
	char dir = e.is_enter ? '>' : '<';
	printf("%c %s(", dir, e.name.c_str());

	for(uint32_t k = 0; k < e.info->nparams; k++) {
		if(k != 0) {
			printf(", ");
		}
		print_param(&e.info->params[k]);
	}

	printf(")\n");
}

void TextFormatter::end_category() {
	printf("\n");
}

void TextFormatter::end() {
	// Nothing to do for text format
}

void TextFormatter::print_param(const struct ppm_param_info* param) {
	printf("%s **%s**", param_type_to_string(param->type), param->name);

	if(is_flag_type(param->type) && param->info) {
		auto flag_info = static_cast<const ppm_name_value*>(param->info);

		printf(": ");
		for(size_t i = 0; flag_info[i].name != NULL; i++) {
			if(i != 0) {
				printf(", ");
			}
			printf("%s", flag_info[i].name);
		}
	}
}

// ============================================================================
// MarkdownFormatter implementation
// ============================================================================

void MarkdownFormatter::begin(const std::string& schema_version) {
	printf("The events below are valid for Falco *Schema Version*: %s\n", schema_version.c_str());
}

void MarkdownFormatter::begin_category(const std::string& category) {
	printf("## %s\n\n", category.c_str());
	printf("Default | Dir | Name | Params \n");
	printf(":-------|:----|:-----|:-----\n");
	m_first_event_in_category = true;
}

void MarkdownFormatter::print_event(const event_entry& e) {
	char dir = e.is_enter ? '>' : '<';

	printf(e.available ? "Yes" : "No");
	printf(" | `%c` | `%s` | ", dir, e.name.c_str());

	for(uint32_t k = 0; k < e.info->nparams; k++) {
		if(k != 0) {
			printf(", ");
		}
		print_param(&e.info->params[k]);
	}

	printf("\n");
}

void MarkdownFormatter::end_category() {
	printf("\n");
}

void MarkdownFormatter::end() {
	// Nothing to do for markdown format
}

void MarkdownFormatter::print_param(const struct ppm_param_info* param) {
	printf("%s **%s**", param_type_to_string(param->type), param->name);

	if(is_flag_type(param->type) && param->info) {
		auto flag_info = static_cast<const ppm_name_value*>(param->info);

		printf(": ");
		for(size_t i = 0; flag_info[i].name != NULL; i++) {
			if(i != 0) {
				printf(", ");
			}
			printf("*%s*", flag_info[i].name);
		}
	}
}

// ============================================================================
// JsonFormatter implementation
// ============================================================================

void JsonFormatter::begin(const std::string& schema_version) {
	m_root = nlohmann::json::object();
	m_root["schema_version"] = schema_version;
}

void JsonFormatter::begin_category(const std::string& category) {
	m_current_category = nlohmann::json::array();
	m_current_category_name = category;
}

void JsonFormatter::print_event(const event_entry& e) {
	m_current_category.push_back(event_to_json(e));
}

void JsonFormatter::end_category() {
	m_root[m_current_category_name] = m_current_category;
}

void JsonFormatter::end() {
	printf("%s\n", m_root.dump(2).c_str());
}

nlohmann::json JsonFormatter::event_to_json(const event_entry& e) {
	nlohmann::json event;
	event["name"] = e.name;
	event["dir"] = e.is_enter ? ">" : "<";
	event["available"] = e.available;

	nlohmann::json params = nlohmann::json::array();
	for(uint32_t k = 0; k < e.info->nparams; k++) {
		nlohmann::json param;
		param["type"] = param_type_to_string(e.info->params[k].type);
		param["name"] = e.info->params[k].name;

		if(is_flag_type(e.info->params[k].type) && e.info->params[k].info) {
			auto flag_info = static_cast<const ppm_name_value*>(e.info->params[k].info);
			nlohmann::json flags = nlohmann::json::array();
			for(size_t i = 0; flag_info[i].name != NULL; i++) {
				flags.push_back(flag_info[i].name);
			}
			param["flags"] = flags;
		}

		params.push_back(param);
	}
	event["params"] = params;

	return event;
}
