#
# Copyright (C) 2019 The Falco Authors.
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

# GNU standard installation directories' definitions
include(GNUInstallDirs)

if(NOT DEFINED FALCO_ETC_DIR)
  set(FALCO_ETC_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/falco")
endif()

if(NOT DEFINED FALCO_RULES_DEST_FILENAME)
  set(FALCO_RULES_DEST_FILENAME "falco_rules.yaml")
  set(FALCO_LOCAL_RULES_DEST_FILENAME "falco_rules.local.yaml")
  set(FALCO_APP_RULES_DEST_FILENAME "application_rules.yaml")
endif()


if(DEFINED FALCO_COMPONENT) # Allow a slim version of Falco to be embedded in other projects, intentionally *not* installing all rulesets.
  install(
    FILES falco_rules.yaml
    COMPONENT "${FALCO_COMPONENT}"
    DESTINATION "${FALCO_ETC_DIR}"
    RENAME "${FALCO_RULES_DEST_FILENAME}")

  install(
    FILES falco_rules.local.yaml
    COMPONENT "${FALCO_COMPONENT}"
    DESTINATION "${FALCO_ETC_DIR}"
    RENAME "${FALCO_LOCAL_RULES_DEST_FILENAME}")
else() # Default Falco installation
  install(
    FILES falco_rules.yaml
    DESTINATION "${FALCO_ETC_DIR}"
    RENAME "${FALCO_RULES_DEST_FILENAME}"
    COMPONENT "${FALCO_COMPONENT_NAME}")

  install(
    FILES falco_rules.local.yaml
    DESTINATION "${FALCO_ETC_DIR}"
    RENAME "${FALCO_LOCAL_RULES_DEST_FILENAME}"
    COMPONENT "${FALCO_COMPONENT_NAME}")

  install(
    FILES application_rules.yaml
    DESTINATION "${FALCO_ETC_DIR}/rules.available"
    RENAME "${FALCO_APP_RULES_DEST_FILENAME}"
    COMPONENT "${FALCO_COMPONENT_NAME}")

  install(DIRECTORY DESTINATION "${FALCO_ETC_DIR}/rules.d" COMPONENT "${FALCO_COMPONENT_NAME}")
endif()
