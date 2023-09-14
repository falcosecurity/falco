# SPDX-License-Identifier: Apache-2.0
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
set(PLUGINS_DOWNLOAD_BUCKET "stable")

string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} PLUGINS_SYSTEM_NAME)

if(NOT DEFINED PLUGINS_COMPONENT_NAME)
    set(PLUGINS_COMPONENT_NAME "${CMAKE_PROJECT_NAME}-plugins")
endif()

# k8saudit
set(PLUGIN_K8S_AUDIT_VERSION "0.6.0")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_K8S_AUDIT_HASH "560e8f8dc8fd169e524d95462d65b5227415a7a157442e82383c7d9f456ce58f")
else() # aarch64
    set(PLUGIN_K8S_AUDIT_HASH "e4757af1bac42b21c5937340790841dedc3805759050a6ffb22d1761e1dd1d31")
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
  URL_HASH "SHA256=44cee2fb88312d889213e1dbe1b9902d0a3f5c594cce73b2cac8e54fb51321b7"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/k8saudit-rules-prefix/src/k8saudit-rules/k8s_audit_rules.yaml" DESTINATION "${FALCO_ETC_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

# cloudtrail
set(PLUGIN_CLOUDTRAIL_VERSION "0.8.0")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_CLOUDTRAIL_HASH "13ba77602c0859936f6e3b00f93bd218c463300c6a797b694a0d5aeecde13976")
else() # aarch64
    set(PLUGIN_CLOUDTRAIL_HASH "a01730738e9d5769f69957a204c8afe528b059e9a22f59792dfc65e19d6a43db")
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
  URL_HASH "SHA256=27f2fc0a74d39476ad968a61318dec65a82b109c4a462b9fa22be45425ddaaad"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/cloudtrail-rules-prefix/src/cloudtrail-rules/aws_cloudtrail_rules.yaml" DESTINATION "${FALCO_ETC_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

# json
set(PLUGIN_JSON_VERSION "0.7.0")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_JSON_HASH "a7bf52009a935f22b473724f722566fde27aec5c7d618ecd426eed81e477e94d")
else() # aarch64
    set(PLUGIN_JSON_HASH "9cd65fac3f1cbc7f723b69671d42d35901cd322a23d8f2b9dc95fb0593918a7e")
endif()

ExternalProject_Add(
  json-plugin
  URL "https://download.falco.org/plugins/${PLUGINS_DOWNLOAD_BUCKET}/json-${PLUGIN_JSON_VERSION}-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=${PLUGIN_JSON_HASH}"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/json-plugin-prefix/src/json-plugin/libjson.so" DESTINATION "${FALCO_PLUGINS_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")
