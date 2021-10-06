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
#

include(ExternalProject)

set(PLUGINS_PREFIX ${CMAKE_BINARY_DIR}/plugins-prefix)
set(PLUGINS_DIR ${CMAKE_CURRENT_BINARY_DIR}/plugins)
message(STATUS "Using bundled plugins in ${PLUGINS_DIR}")

file(MAKE_DIRECTORY ${PLUGINS_DIR})

ExternalProject_Add(
  plugins
  PREFIX ${PLUGINS_PREFIX}
  GIT_REPOSITORY "https://github.com/falcosecurity/plugins.git"
  GIT_TAG "0.1.0-rc1"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND "make"
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND
    ${CMAKE_COMMAND} -E copy
    ${PLUGINS_PREFIX}/src/plugins/plugins/cloudtrail/libcloudtrail.so
    ${PLUGINS_PREFIX}/src/plugins/plugins/json/libjson.so
    ${PLUGINS_DIR})

install(FILES "${PLUGINS_DIR}/libcloudtrail.so" "${PLUGINS_DIR}/libjson.so" DESTINATION "${FALCO_PLUGINS_DIR}")