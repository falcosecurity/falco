#
# Copyright (C) 2021 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

set(FALCO_ENGINE_EMBEDDABLE_SOURCE_FILES
    falco_engine_embeddable.cpp)

set(
  FALCO_LIBRARIES
  falco_engine
  sinsp
  "${LIBYAML_LIB}"
  "${YAMLCPP_LIB}"
)

add_library(falco_engine_embeddable STATIC ${FALCO_ENGINE_EMBEDDABLE_SOURCE_FILES})
add_dependencies(falco_engine_embeddable falco_engine)

target_include_directories(
  falco_engine_embeddable
  PUBLIC
    "${PROJECT_SOURCE_DIR}/userspace/engine"
    "${LUAJIT_INCLUDE}"
    "${NJSON_INCLUDE}"
    "${TBB_INCLUDE_DIR}"
    "${STRING_VIEW_LITE_INCLUDE}"
    "${LIBSCAP_INCLUDE_DIRS}"
    "${LIBSINSP_INCLUDE_DIRS}"
    "${PROJECT_BINARY_DIR}/userspace/engine")

target_link_libraries(falco_engine_embeddable ${FALCO_LIBRARIES})

#add_custom_target(example ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/example)
#add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/example COMMAND go build ${CMAKE_CURRENT_SOURCE_DIR}/example.go -o ${CMAKE_CURRENT_BINARY_DIR}/example)

