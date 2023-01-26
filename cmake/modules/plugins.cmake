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

string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} PLUGINS_SYSTEM_NAME)

if(NOT DEFINED PLUGINS_COMPONENT_NAME)
    set(PLUGINS_COMPONENT_NAME "${CMAKE_PROJECT_NAME}-plugins")
endif()

set(PLUGIN_K8S_AUDIT_VERSION "0.5.0")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_K8S_AUDIT_HASH "c4abb288df018940be8e548340a74d39623b69142304e01523ea189bc698bc80")
else() # aarch64
    set(PLUGIN_K8S_AUDIT_HASH "3bcc849d9f95a3fa519b4592d0947149e492b530fb935a3f98f098e234b7baa7")
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
  URL_HASH "SHA256=4383c69ba0ad63a127667c05618c37effc5297e6a7e68a1492acb0e48386540e"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/k8saudit-rules-prefix/src/k8saudit-rules/k8s_audit_rules.yaml" DESTINATION "${FALCO_ETC_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

set(PLUGIN_CLOUDTRAIL_VERSION "0.7.0")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_CLOUDTRAIL_HASH "85d94d8f5915804d5a30ff2f056e51de27d537f1fd1115050b4f4be6d32588cf")
else() # aarch64
    set(PLUGIN_CLOUDTRAIL_HASH "61ae471ee41e76680da9ab66f583d1ec43a2e48fbad8c157caecef56e4aa5fb7")
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
  URL_HASH "SHA256=c805be29ddc14fbffa29f7d6ee4f7e968a3bdb42da5f5483e5e6de273e8850c8"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

  install(FILES "${PROJECT_BINARY_DIR}/cloudtrail-rules-prefix/src/cloudtrail-rules/aws_cloudtrail_rules.yaml" DESTINATION "${FALCO_ETC_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

set(PLUGIN_JSON_VERSION "0.6.0")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(PLUGIN_JSON_HASH "15fb7eddd978e8bb03f05412e9446e264e4548d7423b3d724b99d6d87a8c1b27")
else() # aarch64
    set(PLUGIN_JSON_HASH "4db23f35a750e10a5b7b54c9aa469a7587705e7faa22927e941b41f3c5533e9f")
endif()

ExternalProject_Add(
  json-plugin
  URL "https://download.falco.org/plugins/stable/json-${PLUGIN_JSON_VERSION}-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=${PLUGIN_JSON_HASH}"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/json-plugin-prefix/src/json-plugin/libjson.so" DESTINATION "${FALCO_PLUGINS_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")
