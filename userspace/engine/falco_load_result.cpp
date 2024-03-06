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

#include "falco_load_result.h"

static const std::string error_codes[] = {
	"LOAD_ERR_FILE_READ",
	"LOAD_ERR_YAML_PARSE",
	"LOAD_ERR_YAML_VALIDATE",
	"LOAD_ERR_COMPILE_CONDITION",
	"LOAD_ERR_COMPILE_OUTPUT",
	"LOAD_ERR_VALIDATE",
	"LOAD_ERR_EXTENSION"
};

const std::string& falco::load_result::error_code_str(error_code ec)
{
	return error_codes[ec];
}

static const std::string error_strings[] = {
	"File read error",
	"YAML parse error",
	"Error validating internal structure of YAML file",
	"Error compiling condition",
	"Error compiling output",
	"Error validating rule/macro/list/exception objects",
	"Error in extension item"
};

const std::string& falco::load_result::error_str(error_code ec)
{
	return error_strings[ec];
}

static const std::string error_descs[] = {
	"This occurs when falco can not read a given file. Check permissions and whether the file exists.",
	"This occurs when the rules content is not valid YAML.",
	"This occurs when the internal structure of the YAML file is incorrect. Examples include not consisting of a sequence of maps, a given rule/macro/list item not having required keys, values not having the right type (e.g. the items property of a list not being a sequence), etc.",
	"This occurs when a condition string can not be compiled to a filter object.",
	"This occurs when an output string can not be compiled to an output object.",
	"This occurs when a rule/macro/list item is incorrect. Examples include a condition field referring to an undefined macro, falco engine/plugin version mismatches, items with append without any existing item, exception fields/comps having different lengths, etc.",
	"This occurs when there is an error in an extension item"
};

const std::string& falco::load_result::error_desc(error_code ec)
{
	return error_strings[ec];
}

static const std::string warning_codes[] = {
	"LOAD_UNKNOWN_SOURCE",
	"LOAD_UNSAFE_NA_CHECK",
	"LOAD_NO_EVTTYPE",
	"LOAD_UNKNOWN_FILTER",
	"LOAD_UNUSED_MACRO",
	"LOAD_UNUSED_LIST",
	"LOAD_UNKNOWN_ITEM",
	"LOAD_DEPRECATED_ITEM",
	"LOAD_WARNING_EXTENSION",
	"LOAD_APPEND_NO_VALUES"
};

const std::string& falco::load_result::warning_code_str(warning_code wc)
{
	return warning_codes[wc];
}

static const std::string warning_strings[] = {
	"Unknown event source",
	"Unsafe <NA> comparison in condition",
	"Condition has no event-type restriction",
	"Unknown field or event-type in condition or output",
	"Unused macro",
	"Unused list",
	"Unknown rules file item",
	"Used deprecated item",
	"Warning in extension item",
	"Overriding/appending with no values"
};

const std::string& falco::load_result::warning_str(warning_code wc)
{
	return warning_strings[wc];
}

static const std::string warning_descs[] = {
	"A rule has a unknown event source. This can occur when reading rules content without having a corresponding plugin loaded, etc. The rule will be silently ignored.",
	"Comparing a field value with <NA> is unsafe and can lead to unpredictable behavior of the rule condition. If you need to check for the existence of a field, consider using the 'exists' operator instead.",
	"A rule condition matches too many evt.type values. This has a significant performance penalty. Make the condition more specific by adding an evt.type field or further restricting the number of evt.type values in the condition.",
	"A rule condition or output refers to a field or evt.type that does not exist. This is normally an error, but if a rule has a skip-if-unknown-filter property, the error is downgraded to a warning.",
	"A macro is defined in the rules content but is not used by any other macro or rule.",
	"A list is defined in the rules content but is not used by any other list, macro, or rule.",
	"An unknown top-level object is in the rules content. It will be ignored.",
	"A deprecated item is employed by lists, macros, or rules.",
	"An extension item has a warning",
	"A rule exception is overriding/appending with no values"
};

const std::string& falco::load_result::warning_desc(warning_code wc)
{
	return warning_descs[wc];
}
