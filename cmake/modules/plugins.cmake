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

if(NOT DEFINED PLUGINS_COMPONENT_NAME)
    set(PLUGINS_COMPONENT_NAME "${CMAKE_PROJECT_NAME}-plugins")
endif()

set(PLUGIN_K8S_AUDIT_VERSION "0.1.0")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_K8S_AUDIT_HASH "57863925a1e5817cb95970f532ffe3d8dfbbb5d60dd58514729b8598e4d30d96")
else() # aarch64
    set(PLUGIN_K8S_AUDIT_HASH "0142670fa0413c057fcd8c138bd9f7211858921037f99295ada22dca8c4208eb")
endif()

ExternalProject_Add(
  k8saudit-plugin
  URL "https://download.falco.org/plugins/stable/k8saudit-${PLUGIN_K8S_AUDIT_VERSION}-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=${PLUGIN_K8S_AUDIT_HASH}"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/k8saudit-plugin-prefix/src/k8saudit-plugin/libk8saudit.so" DESTINATION "${FALCO_PLUGINS_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

ExternalProject_Add(
  k8saudit-rules
  URL "https://download.falco.org/plugins/stable/k8saudit-rules-${PLUGIN_K8S_AUDIT_VERSION}.tar.gz"
  URL_HASH "SHA256=0400918b63e61c61ced9a4196d03f795df1b257c44c68717380415a4806f08d7"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/k8saudit-rules-prefix/src/k8saudit-rules/k8s_audit_rules.yaml" DESTINATION "${FALCO_ETC_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

set(PLUGIN_CLOUDTRAIL_VERSION "0.3.0")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_CLOUDTRAIL_HASH "45a192b10e9bbfc82f4216b071afefd7fba56e02e856e37186430d40160e5d64")
else() # aarch64
    set(PLUGIN_CLOUDTRAIL_HASH "bae3a7f0d6149dc87fd9c96d197ccfb5fae9416d01ff49cfac382e7efcaf737f")
endif()

ExternalProject_Add(
  cloudtrail-plugin
  URL "https://download.falco.org/plugins/stable/cloudtrail-${PLUGIN_CLOUDTRAIL_VERSION}-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=${PLUGIN_CLOUDTRAIL_HASH}"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/cloudtrail-plugin-prefix/src/cloudtrail-plugin/libcloudtrail.so" DESTINATION "${FALCO_PLUGINS_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

ExternalProject_Add(
  cloudtrail-rules
  URL "https://download.falco.org/plugins/stable/cloudtrail-rules-${PLUGIN_CLOUDTRAIL_VERSION}.tar.gz"
  URL_HASH "SHA256=8ed676f9801d987a26854827beb176eb9164dec3b09a714406348fe1096f7c6c"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

  install(FILES "${PROJECT_BINARY_DIR}/cloudtrail-rules-prefix/src/cloudtrail-rules/aws_cloudtrail_rules.yaml" DESTINATION "${FALCO_ETC_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

set(PLUGIN_JSON_VERSION "0.3.0")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_JSON_HASH "e57cc4d2850370a16caeca35ceff96c9c906970d86f2009b70805b8622964178")
else() # aarch64
    set(PLUGIN_JSON_HASH "a41326fcd570e5439735a04141a460a4e9b5d999cf0e4091d69087363284c45c")
endif()

ExternalProject_Add(
  json-plugin
  URL "https://download.falco.org/plugins/stable/json-${PLUGIN_JSON_VERSION}-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=${PLUGIN_JSON_HASH}"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/json-plugin-prefix/src/json-plugin/libjson.so" DESTINATION "${FALCO_PLUGINS_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")
