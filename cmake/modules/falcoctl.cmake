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

string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} FALCOCTL_SYSTEM_NAME)

set(FALCOCTL_VERSION "0.3.0-rc5")

if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(FALCOCTL_SYSTEM_PROC_GO "amd64")
    set(FALCOCTL_HASH "012b4a45dccc3f62d2574f5481e154585ff8cb0c43d40ad9a7f49a057b311621")
else() # aarch64
    set(FALCOCTL_SYSTEM_PROC_GO "arm64")
    set(FALCOCTL_HASH "e35a225c51ce45d1b53a3392caee60e1eeea9a1c885d43d63b2be16cc1b66c7a")
endif()

ExternalProject_Add(
        falcoctl
        URL "https://github.com/falcosecurity/falcoctl/releases/download/v${FALCOCTL_VERSION}/falcoctl_${FALCOCTL_VERSION}_${FALCOCTL_SYSTEM_NAME}_${FALCOCTL_SYSTEM_PROC_GO}.tar.gz"
        URL_HASH "SHA256=${FALCOCTL_HASH}"
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND "")

install(PROGRAMS "${PROJECT_BINARY_DIR}/falcoctl-prefix/src/falcoctl/falcoctl" DESTINATION "${FALCO_BIN_DIR}" COMPONENT "${FALCO_COMPONENT_NAME}")
