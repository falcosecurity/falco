# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 The Falco Authors.
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

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	# Systemd
	file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/scripts/systemd)
	configure_file(
		"${PROJECT_SOURCE_DIR}/scripts/systemd/falco-kmod-inject.service"
		"${PROJECT_BINARY_DIR}/scripts/systemd" COPYONLY
	)
	configure_file(
		"${PROJECT_SOURCE_DIR}/scripts/systemd/falco-kmod.service"
		"${PROJECT_BINARY_DIR}/scripts/systemd" COPYONLY
	)
	configure_file(
		"${PROJECT_SOURCE_DIR}/scripts/systemd/falco-modern-bpf.service"
		"${PROJECT_BINARY_DIR}/scripts/systemd" COPYONLY
	)
	configure_file(
		"${PROJECT_SOURCE_DIR}/scripts/systemd/falco-custom.service"
		"${PROJECT_BINARY_DIR}/scripts/systemd" COPYONLY
	)
	configure_file(
		"${PROJECT_SOURCE_DIR}/scripts/systemd/falcoctl-artifact-follow.service"
		"${PROJECT_BINARY_DIR}/scripts/systemd" COPYONLY
	)

	# Expand shared package helpers before embedding them in each scriptlet.
	configure_file(packaging/functions.sh.in packaging/functions.sh @ONLY)
	file(READ "${CMAKE_CURRENT_BINARY_DIR}/packaging/functions.sh" FALCO_PACKAGE_FUNCTIONS)

	foreach(script preinst postinst prerm postrm)
		configure_file(debian/${script}.in debian/${script} @ONLY)
	endforeach()
	foreach(script preinstall postinstall posttrans preuninstall postuninstall)
		configure_file(rpm/${script}.in rpm/${script} @ONLY)
	endforeach()
endif()

# Install Falcoctl config file
if(NOT WIN32
   AND NOT APPLE
   AND NOT EMSCRIPTEN
   AND NOT MUSL_OPTIMIZED_BUILD
)
	if(NOT DEFINED FALCOCTL_ETC_DIR)
		set(FALCOCTL_ETC_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/falcoctl")
	endif()
	set(FALCOCTL_DRIVER_TYPES_LIST "")
	if(BUILD_FALCO_MODERN_BPF)
		list(APPEND FALCOCTL_DRIVER_TYPES_LIST "modern_ebpf")
	endif()
	if(BUILD_DRIVER)
		list(APPEND FALCOCTL_DRIVER_TYPES_LIST "kmod")
	endif()
	string(REPLACE ";" ", " FALCOCTL_DRIVER_TYPES "${FALCOCTL_DRIVER_TYPES_LIST}")
	configure_file(
		${CMAKE_CURRENT_SOURCE_DIR}/falcoctl/falcoctl.yaml.in
		${PROJECT_BINARY_DIR}/scripts/falcoctl/falcoctl.yaml
	)
	install(
		FILES ${PROJECT_BINARY_DIR}/scripts/falcoctl/falcoctl.yaml
		DESTINATION "${FALCOCTL_ETC_DIR}"
		COMPONENT "${FALCO_COMPONENT_NAME}"
	)
endif()
