# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under
# the License.
#

include(ExternalProject)

option(ADD_FALCOCTL_DEPENDENCY "Add falcoctl dependency while building falco" ON)

if(ADD_FALCOCTL_DEPENDENCY)
	string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} FALCOCTL_SYSTEM_NAME)

	set(FALCOCTL_VERSION "0.11.0")

	message(STATUS "Building with falcoctl: ${FALCOCTL_VERSION}")

	if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
		set(FALCOCTL_SYSTEM_PROC_GO "amd64")
		set(FALCOCTL_HASH "b9d0e0f50813e7172a945f36f70c5c3c16a677ab4c85b35b6f7a155bc92768fc")
	else() # aarch64
		set(FALCOCTL_SYSTEM_PROC_GO "arm64")
		set(FALCOCTL_HASH "689c625d1d414cbf53d39ef94083a53dda3ea4ac4908799fb85f4519e21442e0")
	endif()

	ExternalProject_Add(
		falcoctl
		URL "https://github.com/falcosecurity/falcoctl/releases/download/v${FALCOCTL_VERSION}/falcoctl_${FALCOCTL_VERSION}_${FALCOCTL_SYSTEM_NAME}_${FALCOCTL_SYSTEM_PROC_GO}.tar.gz"
		URL_HASH "SHA256=${FALCOCTL_HASH}"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ""
		INSTALL_COMMAND ""
	)

	install(
		PROGRAMS "${PROJECT_BINARY_DIR}/falcoctl-prefix/src/falcoctl/falcoctl"
		DESTINATION "${FALCO_BIN_DIR}"
		COMPONENT "${FALCO_COMPONENT_NAME}"
	)
	install(
		DIRECTORY
		DESTINATION "${FALCO_ABSOLUTE_SHARE_DIR}/plugins"
		COMPONENT "${FALCO_COMPONENT_NAME}"
	)
else()
	message(STATUS "Won't build with falcoctl")
endif()
