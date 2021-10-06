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
set(PLUGINS_VERSION "0.1.0-rc1")
string(TOLOWER ${CMAKE_SYSTEM_NAME} PLUGIN_SYSTEM_NAME)
set(PLUGINS_FULL_VERSION "falcosecurity-plugins-${PLUGINS_VERSION}-${PLUGIN_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}")
message(STATUS "Using bundled plugins in ${PLUGINS_PREFIX}")

ExternalProject_Add(
  plugins
  PREFIX ${PLUGINS_PREFIX}
  URL "https://download.falco.org/plugins/${PLUGINS_FULL_VERSION}.tar.gz"
  URL_HASH "SHA256=3750b3e5120aba9c6d388f6bfdc3c150564edd21779876c3bcf7ec9d3afb66ad"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PLUGINS_PREFIX}/src/plugins/cloudtrail/libcloudtrail.so" "${PLUGINS_PREFIX}/src/plugins/json/libjson.so" DESTINATION "${FALCO_PLUGINS_DIR}")