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

string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} PLUGINS_SYSTEM_NAME)

# todo(jasondellaluce): switch this to a stable version once this plugin gets
# released with a 1.0.0 required plugin api version
ExternalProject_Add(
  cloudtrail-plugin
  URL "https://download.falco.org/plugins/dev/cloudtrail-0.2.5-0.2.5-3%2B3068d86-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=6c697a2116eec73386ab19a0e13f6906e6697e82138f3d6435720976df3af6c2"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/cloudtrail-plugin-prefix/src/cloudtrail-plugin/libcloudtrail.so" DESTINATION "${FALCO_PLUGINS_DIR}")

# todo(jasondellaluce): switch this to a stable version once this plugin gets
# released with a 1.0.0 required plugin api version
ExternalProject_Add(
  json-plugin
  URL "https://download.falco.org/plugins/dev/json-0.2.2-0.2.2-19%2B3068d86-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=e5c8cf4290b700ae92e80f693aa5a0223d917d637001fdc872430e57a1e625bc"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/json-plugin-prefix/src/json-plugin/libjson.so" DESTINATION "${FALCO_PLUGINS_DIR}")
