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

# GNU standard installation directories' definitions
include(GNUInstallDirs)

if(NOT DEFINED FALCO_ETC_DIR)
  set(FALCO_ETC_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/falco")
endif()

if(DEFINED FALCO_COMPONENT) # Allow a slim version of Falco, intentionally *not* installing rules files.
  install(
    FILES falco_rules.local.yaml
    COMPONENT "${FALCO_COMPONENT}"
    DESTINATION "${FALCO_ETC_DIR}"
    RENAME "${FALCO_LOCAL_RULES_DEST_FILENAME}")
  install(DIRECTORY DESTINATION "${FALCO_ETC_DIR}/rules.d" COMPONENT "${FALCO_COMPONENT_NAME}")
endif()
