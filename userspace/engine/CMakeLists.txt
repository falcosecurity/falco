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

add_subdirectory(lua)

set(FALCO_ENGINE_SOURCE_FILES
    rules.cpp
    falco_common.cpp
    falco_engine.cpp
    falco_utils.cpp
    json_evt.cpp
    ruleset.cpp
    formats.cpp)

add_library(falco_engine STATIC ${FALCO_ENGINE_SOURCE_FILES})
add_dependencies(falco_engine njson lyaml string-view-lite)

if(USE_BUNDLED_DEPS)
  add_dependencies(falco_engine libyaml)
endif()

if(MINIMAL_BUILD)
  target_include_directories(
    falco_engine
    PUBLIC
      "${LUAJIT_INCLUDE}"
      "${NJSON_INCLUDE}"
      "${TBB_INCLUDE_DIR}"
      "${STRING_VIEW_LITE_INCLUDE}"
      "${LIBSCAP_INCLUDE_DIRS}"
      "${LIBSINSP_INCLUDE_DIRS}"
      "${PROJECT_BINARY_DIR}/userspace/engine"
      "${PROJECT_BINARY_DIR}/userspace/engine/lua")
else()
  target_include_directories(
    falco_engine
    PUBLIC
      "${LUAJIT_INCLUDE}"
      "${NJSON_INCLUDE}"
      "${CURL_INCLUDE_DIR}"
      "${TBB_INCLUDE_DIR}"
      "${STRING_VIEW_LITE_INCLUDE}"
      "${LIBSCAP_INCLUDE_DIRS}"
      "${LIBSINSP_INCLUDE_DIRS}"
      "${PROJECT_BINARY_DIR}/userspace/engine"
      "${PROJECT_BINARY_DIR}/userspace/engine/lua")
endif()

target_link_libraries(falco_engine "${FALCO_SINSP_LIBRARY}" "${LYAML_LIB}" "${LIBYAML_LIB}" luafiles)
