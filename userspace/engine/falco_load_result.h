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

#include <functional>
#include <string>
#include <nlohmann/json.hpp>

namespace falco
{

// Represents the result of loading a rules file.
class load_result {
public:

	enum error_code {
		LOAD_ERR_FILE_READ = 0,
		LOAD_ERR_YAML_PARSE,
		LOAD_ERR_YAML_VALIDATE,
		LOAD_ERR_COMPILE_CONDITION,
		LOAD_ERR_COMPILE_OUTPUT,
		LOAD_ERR_VALIDATE,
		LOAD_ERR_EXTENSION
	};

	// The error code as a string
	static const std::string& error_code_str(error_code ec);

	// A short string representation of the error
	static const std::string& error_str(error_code ec);

	// A longer description of what the error represents and the
	// impact.
	static const std::string& error_desc(error_code ec);

	enum warning_code {
		LOAD_UNKNOWN_SOURCE = 0,
		LOAD_UNSAFE_NA_CHECK,
		LOAD_NO_EVTTYPE,
		LOAD_UNKNOWN_FILTER,
		LOAD_UNUSED_MACRO,
		LOAD_UNUSED_LIST,
		LOAD_UNKNOWN_ITEM,
		LOAD_DEPRECATED_ITEM,
		LOAD_WARNING_EXTENSION,
		LOAD_APPEND_NO_VALUES,
		LOAD_EXCEPTION_NAME_NOT_UNIQUE,
		LOAD_INVALID_MACRO_NAME,
		LOAD_INVALID_LIST_NAME,
		LOAD_COMPILE_CONDITION
	};

	virtual ~load_result() = default;

	// The warning code as a string
	static const std::string& warning_code_str(warning_code ec);

	// A short string representation of the warning
	static const std::string& warning_str(warning_code ec);

	// A longer description of what the warning represents and the
	// impact.
	static const std::string& warning_desc(warning_code ec);

	// If true, the rules were loaded successfully and can be used
	// against events. If false, there were one or more
	// errors--use one of the as_xxx methods to return information
	// about why the rules could not be loaded.
	virtual bool successful() = 0;

	// If true, there were one or more warnings. successful() and
	// has_warnings() can both be true if there were only warnings.
	virtual bool has_warnings() = 0;

	// Return json schema validation status.
	virtual std::string schema_validation() = 0;

	// This represents a set of rules contents as a mapping from
	// rules content name (usually filename) to rules content. The
	// rules content is actually a reference to the actual string
	// to avoid copies. Using reference_wrapper allows the
	// reference to be held in the stl map (bare references can't
	// be copied/assigned, but reference_wrappers can).
	//
	// It's used in the as_string/as_json() methods below.
	typedef std::map<std::string, std::reference_wrapper<const std::string>> rules_contents_t;

	// This contains a human-readable version of the result,
	// suitable for display to end users.
	//
	// The provided rules_contents_t should map from content name
	// to rules content (reference) for each rules_content that has
	// been passed to rule_loader::compile() or
	// rule_reader::load().
	//
	// When verbose is true, the returned value has full details
	// on the result including document locations/context.
	//
	// When verbose is false, the returned value is a short string
	// with the success value and a list of
	// errors/warnings. Suitable for simple one-line display.
	virtual const std::string& as_string(bool verbose, const rules_contents_t& contents) = 0;

	// This contains the full result structure as json, suitable
	// for automated parsing/interpretation downstream.
	virtual const nlohmann::json& as_json(const rules_contents_t& contents) = 0;
};

} // namespace falco
