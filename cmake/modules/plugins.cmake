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

# todo(jasondellaluce): switch this to a stable version once this plugin gets
# released with a 1.0.0 required plugin api version
ExternalProject_Add(
  k8saudit-plugin
  URL "https://download.falco.org/plugins/dev/k8saudit-0.1.0-0.0.0-0%2B680536f-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=d2d4080a67445b9c5db6162e18e09c4eb9a32b0324877da584f8fa936595cd43"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/k8saudit-plugin-prefix/src/k8saudit-plugin/libk8saudit.so" DESTINATION "${FALCO_PLUGINS_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

ExternalProject_Add(
  k8saudit-rules
  URL "https://download.falco.org/plugins/dev/k8saudit-rules-0.1.0-0.0.0-0%2B680536f.tar.gz"
  URL_HASH "SHA256=7e283031150b650b0387c6d644a8dbbe992d3f39e35ef3e63eca955889211510"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/k8saudit-rules-prefix/src/k8saudit-rules/k8s_audit_rules.yaml" DESTINATION "${FALCO_ETC_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

# todo(jasondellaluce): switch this to a stable version once this plugin gets
# released with a 1.0.0 required plugin api version
ExternalProject_Add(
  cloudtrail-plugin
  URL "https://download.falco.org/plugins/dev/cloudtrail-0.2.5-0.2.5-125%2B680536f-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=5e949b2ebebb500325d2ec5bbb1ffdf4f7461a144a8f46ab500a1733af006bc2"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/cloudtrail-plugin-prefix/src/cloudtrail-plugin/libcloudtrail.so" DESTINATION "${FALCO_PLUGINS_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

ExternalProject_Add(
  cloudtrail-rules
  URL "https://download.falco.org/plugins/dev/cloudtrail-rules-0.2.5-0.2.5-125%2B680536f.tar.gz"
  URL_HASH "SHA256=1b48708f2e948e8765c25222d3de4ebfd49ed784de72d1177382beb60c7fb343"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

  install(FILES "${PROJECT_BINARY_DIR}/cloudtrail-rules-prefix/src/cloudtrail-rules/aws_cloudtrail_rules.yaml" DESTINATION "${FALCO_ETC_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")

# todo(jasondellaluce): switch this to a stable version once this plugin gets
# released with a 1.0.0 required plugin api version
ExternalProject_Add(
  json-plugin
  URL "https://download.falco.org/plugins/dev/json-0.2.2-0.2.2-141%2B680536f-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
  URL_HASH "SHA256=0d947f3ace8732767fffb02bcb62cc6ee685c51afadc91db7ff3a8576c13e6d6"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

install(FILES "${PROJECT_BINARY_DIR}/json-plugin-prefix/src/json-plugin/libjson.so" DESTINATION "${FALCO_PLUGINS_DIR}" COMPONENT "${PLUGINS_COMPONENT_NAME}")
