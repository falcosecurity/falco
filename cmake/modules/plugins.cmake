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

ExternalProject_Add(
  cloudtrail-plugin
  URL "https://download.falco.org/plugins/stable/cloudtrail-0.2.0-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=917ebc5c3b1ad78d959372baa73ac2e9b18b38f51e1e42bd0974166dc04a964c"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/cloudtrail-plugin-prefix/src/cloudtrail-plugin/libcloudtrail.so" DESTINATION "${FALCO_PLUGINS_DIR}")

ExternalProject_Add(
  json-plugin
  URL "https://download.falco.org/plugins/stable/json-0.2.0-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=250f0b04db7ab08f3bfa5ecd90cc9b39a6992fc2e96b887ed6f319a6ba156fd7"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/json-plugin-prefix/src/json-plugin/libjson.so" DESTINATION "${FALCO_PLUGINS_DIR}")
