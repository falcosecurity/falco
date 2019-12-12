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
#

option(
  BUILD_STATIC_YAMLCPP
  "Build a static version of yaml-cpp (useful for building in Operating Systems that don't have the yaml-cpp package)"
  OFF)

if(NOT BUILD_STATIC_YAMLCPP)
  find_path(YAMLCPP_INCLUDE_DIR NAMES yaml-cpp/yaml.h)
  find_library(YAMLCPP_LIB NAMES yaml-cpp)
  if(YAMLCPP_INCLUDE_DIR AND YAMLCPP_LIB)
    message(STATUS "Found yamlcpp: include: ${YAMLCPP_INCLUDE_DIR}, lib: ${YAMLCPP_LIB}")
  else()
    message(FATAL_ERROR "Couldn't find system yamlcpp")
  endif()
else()
  set(YAMLCPP_SRC "${PROJECT_BINARY_DIR}/yamlcpp-prefix/src/yamlcpp")
  message(STATUS "Using bundled yaml-cpp in '${YAMLCPP_SRC}'")
  set(YAMLCPP_LIB "${YAMLCPP_SRC}/libyaml-cpp.a")
  set(YAMLCPP_INCLUDE_DIR "${YAMLCPP_SRC}/include")
  ExternalProject_Add(
    yamlcpp
    URL "https://github.com/jbeder/yaml-cpp/archive/yaml-cpp-0.6.2.tar.gz"
    URL_MD5 "5b943e9af0060d0811148b037449ef82"
    BUILD_IN_SOURCE 1
    INSTALL_COMMAND "")
endif()
