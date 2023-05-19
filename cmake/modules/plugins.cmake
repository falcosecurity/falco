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
#

include(ExternalProject)

# 'stable' or 'dev'
set(PLUGINS_DOWNLOAD_BUCKET "dev")

string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} PLUGINS_SYSTEM_NAME)

if(NOT DEFINED PLUGINS_COMPONENT_NAME)
    set(PLUGINS_COMPONENT_NAME "${CMAKE_PROJECT_NAME}-plugins")
endif()

# k8saudit
set(PLUGIN_K8S_AUDIT_VERSION "0.5.3-0.5.3-27%2B7b07a4b")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_K8S_AUDIT_HASH "22c15e5aa2c86cf2216cd767f8766047696e9ba637d63c5ae5e00893f0efad9c")
else() # aarch64
    set(PLUGIN_K8S_AUDIT_HASH "564f95031b973296fd7ccdda6c4a4f6820bb6da8106bcd48a549a7fca8c02540")
endif()

ExternalProject_Add(
  k8saudit-plugin
  URL "https://download.falco.org/plugins/${PLUGINS_DOWNLOAD_BUCKET}/k8saudit-${PLUGIN_K8S_AUDIT_VERSION}-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=${PLUGIN_K8S_AUDIT_HASH}"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/k8saudit-plugin-prefix/src/k8saudit-plugin/libk8saudit.so" DESTINATION "${FALCO_PLUGINS_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

ExternalProject_Add(
  k8saudit-rules
  URL "https://download.falco.org/plugins/${PLUGINS_DOWNLOAD_BUCKET}/k8saudit-rules-${PLUGIN_K8S_AUDIT_VERSION}.tar.gz"
  URL_HASH "SHA256=d1add6c4dfe7e8aca85f536fd7577dd0d93662927ab604e6db6757e89b99f2b2"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/k8saudit-rules-prefix/src/k8saudit-rules/k8s_audit_rules.yaml" DESTINATION "${FALCO_ETC_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

# cloudtrail
set(PLUGIN_CLOUDTRAIL_VERSION "0.7.3-0.7.3-27%2B7b07a4b")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_CLOUDTRAIL_HASH "856f5f5505c72776a188ba29633d81e5f21924b20c2cfb5a2da3f8f21410e248")
else() # aarch64
    set(PLUGIN_CLOUDTRAIL_HASH "935a96d68f182cec0f650186355bb245e36fdd884a596442992b55f066993fc1")
endif()

ExternalProject_Add(
  cloudtrail-plugin
  URL "https://download.falco.org/plugins/${PLUGINS_DOWNLOAD_BUCKET}/cloudtrail-${PLUGIN_CLOUDTRAIL_VERSION}-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=${PLUGIN_CLOUDTRAIL_HASH}"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/cloudtrail-plugin-prefix/src/cloudtrail-plugin/libcloudtrail.so" DESTINATION "${FALCO_PLUGINS_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

ExternalProject_Add(
  cloudtrail-rules
  URL "https://download.falco.org/plugins/${PLUGINS_DOWNLOAD_BUCKET}/cloudtrail-rules-${PLUGIN_CLOUDTRAIL_VERSION}.tar.gz"
  URL_HASH "SHA256=4b92cb5f81be0734a87babbd48eb1dc15e1297168024072c3fd02ccee7550b73"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/cloudtrail-rules-prefix/src/cloudtrail-rules/aws_cloudtrail_rules.yaml" DESTINATION "${FALCO_ETC_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

# json
set(PLUGIN_JSON_VERSION "0.6.2-0.6.2-30%2B7b07a4b")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_JSON_HASH "9d3ef271667d9662fd47672b59ccace800ae1cc4f6d4c6d34edc1d9e26a87179")
else() # aarch64
    set(PLUGIN_JSON_HASH "113a632f4dd05ef7c4537fafdc0114fbe736a1da10b8225d8aa1679442157d5b")
endif()

ExternalProject_Add(
  json-plugin
  URL "https://download.falco.org/plugins/${PLUGINS_DOWNLOAD_BUCKET}/json-${PLUGIN_JSON_VERSION}-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=${PLUGIN_JSON_HASH}"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/json-plugin-prefix/src/json-plugin/libjson.so" DESTINATION "${FALCO_PLUGINS_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")
