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
set(PLUGIN_K8S_AUDIT_VERSION "0.6.0-0.5.3-33%2B81ffddd")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_K8S_AUDIT_HASH "990e5c67d3b3c7cf5d30c73d73871b58767171ce7c998c1ca1d94d70c67db290")
else() # aarch64
    set(PLUGIN_K8S_AUDIT_HASH "c3634dfa83c8c8898811ab6b7587ea6d1c6dfffbdfa56def28cab43aaf01f88c")
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
  URL_HASH "SHA256=2e3214fee00a012b32402aad5198df889773fc5f86b8ab87583fbc56ae5fb78c"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/k8saudit-rules-prefix/src/k8saudit-rules/k8s_audit_rules.yaml" DESTINATION "${FALCO_ETC_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

# cloudtrail
set(PLUGIN_CLOUDTRAIL_VERSION "0.8.0-0.7.3-33%2B81ffddd")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_CLOUDTRAIL_HASH "144c297ae4285ea84b04af272f708a8b824f58bc9427a2eb91b467a6285d9e10")
else() # aarch64
    set(PLUGIN_CLOUDTRAIL_HASH "19e7e8e11aaecd16442f65a265d3cd80ffb736ca4d3d8215893900fa0f04b926")
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
  URL_HASH "SHA256=4f51d4bd9679f7f244c225b6fe530323f3536663da26a5b9d94d6953ed4e2cbc"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/cloudtrail-rules-prefix/src/cloudtrail-rules/aws_cloudtrail_rules.yaml" DESTINATION "${FALCO_ETC_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

# json
set(PLUGIN_JSON_VERSION "0.7.0-0.6.2-36%2B81ffddd")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_JSON_HASH "a9d8c595a139df5dc0cf2117127b496c94a9d3a3d0e84c1f18b3ccc9163f5f4a")
else() # aarch64
    set(PLUGIN_JSON_HASH "7d78620395526d1e6a948cc915d1d52a343c2b637c9ac0e3892e76826fcdc2df")
endif()

ExternalProject_Add(
  json-plugin
  URL "https://download.falco.org/plugins/${PLUGINS_DOWNLOAD_BUCKET}/json-${PLUGIN_JSON_VERSION}-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=${PLUGIN_JSON_HASH}"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/json-plugin-prefix/src/json-plugin/libjson.so" DESTINATION "${FALCO_PLUGINS_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")
