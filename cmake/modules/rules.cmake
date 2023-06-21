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

include(GNUInstallDirs)
include(ExternalProject)

# falco_rules.yaml
set(FALCOSECURITY_RULES_FALCO_VERSION "falco-rules-1.0.1")
set(FALCOSECURITY_RULES_FALCO_CHECKSUM "SHA256=2348d43196bbbdea92e3f67fa928721a241b0406d0ef369693bdefcec2b3fa13")
set(FALCOSECURITY_RULES_FALCO_PATH "${PROJECT_BINARY_DIR}/falcosecurity-rules-falco-prefix/src/falcosecurity-rules-falco/falco_rules.yaml")
ExternalProject_Add(
  falcosecurity-rules-falco
  URL "https://download.falco.org/rules/${FALCOSECURITY_RULES_FALCO_VERSION}.tar.gz"
  URL_HASH "${FALCOSECURITY_RULES_FALCO_CHECKSUM}"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
  TEST_COMMAND ""
)

# falco_rules.local.yaml
set(FALCOSECURITY_RULES_LOCAL_PATH "${PROJECT_BINARY_DIR}/falcosecurity-rules-local-prefix/falco_rules.local.yaml")
file(WRITE "${FALCOSECURITY_RULES_LOCAL_PATH}" "# Your custom rules!\n")

if(NOT DEFINED FALCO_ETC_DIR)
  set(FALCO_ETC_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/falco")
endif()

if(NOT DEFINED FALCO_RULES_DEST_FILENAME)
  set(FALCO_RULES_DEST_FILENAME "falco_rules.yaml")
  set(FALCO_LOCAL_RULES_DEST_FILENAME "falco_rules.local.yaml")
endif()

if(DEFINED FALCO_COMPONENT) # Allow a slim version of Falco to be embedded in other projects, intentionally *not* installing all rulesets.
  install(
    FILES "${FALCOSECURITY_RULES_FALCO_PATH}"
    COMPONENT "${FALCO_COMPONENT}"
    DESTINATION "${FALCO_ETC_DIR}"
    RENAME "${FALCO_RULES_DEST_FILENAME}")

  install(
    FILES "${FALCOSECURITY_RULES_LOCAL_PATH}"
    COMPONENT "${FALCO_COMPONENT}"
    DESTINATION "${FALCO_ETC_DIR}"
    RENAME "${FALCO_LOCAL_RULES_DEST_FILENAME}")
else() # Default Falco installation
  install(
    FILES "${FALCOSECURITY_RULES_FALCO_PATH}"
    DESTINATION "${FALCO_ETC_DIR}"
    RENAME "${FALCO_RULES_DEST_FILENAME}"
    COMPONENT "${FALCO_COMPONENT_NAME}")

  install(
    FILES "${FALCOSECURITY_RULES_LOCAL_PATH}"
    DESTINATION "${FALCO_ETC_DIR}"
    RENAME "${FALCO_LOCAL_RULES_DEST_FILENAME}"
    COMPONENT "${FALCO_COMPONENT_NAME}")

  install(DIRECTORY DESTINATION "${FALCO_ETC_DIR}/rules.d" COMPONENT "${FALCO_COMPONENT_NAME}")
endif()
