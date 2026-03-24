# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under
# the License.
#

# Generate a C++ header mapping config keys to their maturity levels by parsing the structured
# comments in falco.yaml.
#
# The expected comment format is:  # [Level] `key` where Level is one of: Stable, Incubating,
# Sandbox, Deprecated.

function(generate_config_maturity YAML_FILE OUTPUT_FILE)
	file(STRINGS "${YAML_FILE}" YAML_LINES)

	set(ENTRIES "")
	set(ENTRY_COUNT 0)

	foreach(LINE ${YAML_LINES})
		# Match lines like: # [Stable] `config_files`
		string(REGEX MATCH "^# \\[(Stable|Incubating|Sandbox|Deprecated)\\] `([^`]+)`" _MATCH
					 "${LINE}"
		)

		if(_MATCH)
			set(LEVEL "${CMAKE_MATCH_1}")
			set(KEY "${CMAKE_MATCH_2}")

			string(TOUPPER "${LEVEL}" LEVEL_UPPER)
			string(APPEND ENTRIES "\t{\"${KEY}\", maturity_level::${LEVEL_UPPER}},\n")
			math(EXPR ENTRY_COUNT "${ENTRY_COUNT} + 1")
		endif()
	endforeach()

	if(ENTRY_COUNT EQUAL 0)
		message(FATAL_ERROR "ConfigMaturity: no maturity tags found in ${YAML_FILE}")
	endif()

	set(HEADER_CONTENT
		"// Auto-generated from falco.yaml — do not edit.
// See: cmake/modules/ConfigMaturity.cmake
#pragma once

#include \"maturity.h\"

#include <array>
#include <string_view>

struct config_maturity_entry {
\tstd::string_view key;
\tmaturity_level level;
};

inline constexpr std::array<config_maturity_entry, ${ENTRY_COUNT}> config_maturity_table = {{
${ENTRIES}}};
"
	)
	file(WRITE "${OUTPUT_FILE}" "${HEADER_CONTENT}")

	message(STATUS "ConfigMaturity: generated ${OUTPUT_FILE} with ${ENTRY_COUNT} entries")
endfunction()
