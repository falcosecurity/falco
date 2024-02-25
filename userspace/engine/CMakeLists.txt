# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

add_library(falco_engine STATIC
    falco_common.cpp
    falco_engine.cpp
    falco_load_result.cpp
    falco_utils.cpp
    filter_ruleset.cpp
    evttype_index_ruleset.cpp
    formats.cpp
    filter_details_resolver.cpp
    filter_macro_resolver.cpp
    filter_warning_resolver.cpp
    stats_manager.cpp
    rule_loader.cpp
    rule_loader_reader.cpp
    rule_loader_collector.cpp
    rule_loader_compiler.cpp
)

if (EMSCRIPTEN)
	target_compile_options(falco_engine PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
endif()

target_include_directories(falco_engine
PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${TBB_INCLUDE_DIR}
)

target_link_libraries(falco_engine
PUBLIC
    sinsp
    nlohmann_json::nlohmann_json
    yaml-cpp
)
