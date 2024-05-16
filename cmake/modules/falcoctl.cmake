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

string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} FALCOCTL_SYSTEM_NAME)

set(FALCOCTL_VERSION "0.8.0-rc5")

if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(FALCOCTL_SYSTEM_PROC_GO "amd64")
    set(FALCOCTL_HASH "a38a8a9331f3221440fa9db5b22241439a81fcec6dc964d965823ab70de6fcc5")
else() # aarch64
    set(FALCOCTL_SYSTEM_PROC_GO "arm64")
    set(FALCOCTL_HASH "6987540bd30b85c7254af40a817e45a9cfe071252bf5ab88bb8acb01979b28a7")
endif()

ExternalProject_Add(
        falcoctl
        URL "https://github.com/falcosecurity/falcoctl/releases/download/v${FALCOCTL_VERSION}/falcoctl_${FALCOCTL_VERSION}_${FALCOCTL_SYSTEM_NAME}_${FALCOCTL_SYSTEM_PROC_GO}.tar.gz"
        URL_HASH "SHA256=${FALCOCTL_HASH}"
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND "")

install(PROGRAMS "${PROJECT_BINARY_DIR}/falcoctl-prefix/src/falcoctl/falcoctl" DESTINATION "${FALCO_BIN_DIR}" COMPONENT "${FALCO_COMPONENT_NAME}")
install(DIRECTORY DESTINATION "${FALCO_ABSOLUTE_SHARE_DIR}/plugins" COMPONENT "${FALCO_COMPONENT_NAME}")
