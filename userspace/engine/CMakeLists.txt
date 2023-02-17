#
# Copyright (C) 2019 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

set(FALCO_ENGINE_SOURCE_FILES
    falco_common.cpp
    falco_engine.cpp
    falco_load_result.cpp
    falco_utils.cpp
    json_evt.cpp
    evttype_index_ruleset.cpp
    formats.cpp
    filter_macro_resolver.cpp
    filter_warning_resolver.cpp
    stats_manager.cpp
    rule_loader.cpp
    rule_loader_reader.cpp
    rule_loader_collector.cpp
    rule_loader_compiler.cpp)

add_library(falco_engine STATIC ${FALCO_ENGINE_SOURCE_FILES})

add_dependencies(falco_engine yamlcpp njson)

if(MINIMAL_BUILD)
  target_include_directories(
    falco_engine
    PUBLIC
      "${NJSON_INCLUDE}"
      "${TBB_INCLUDE_DIR}"
      "${LIBSCAP_INCLUDE_DIRS}"
      "${LIBSINSP_INCLUDE_DIRS}"
      "${YAMLCPP_INCLUDE_DIR}"
      "${PROJECT_BINARY_DIR}/userspace/engine")
else()
  target_include_directories(
    falco_engine
    PUBLIC
      "${NJSON_INCLUDE}"
      "${TBB_INCLUDE_DIR}"
      "${LIBSCAP_INCLUDE_DIRS}"
      "${LIBSINSP_INCLUDE_DIRS}"
      "${YAMLCPP_INCLUDE_DIR}"
      "${PROJECT_BINARY_DIR}/userspace/engine")
endif()

target_link_libraries(falco_engine "${FALCO_SINSP_LIBRARY}" "${YAMLCPP_LIB}")
