#
# Copyright (C) 2021 The Falco Authors.
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Systemd
file(COPY "${PROJECT_SOURCE_DIR}/scripts/systemd/falco.target"
		DESTINATION "${PROJECT_BINARY_DIR}/scripts/systemd")
file(COPY "${PROJECT_SOURCE_DIR}/scripts/systemd/falco-kmod-inject.service"
		DESTINATION "${PROJECT_BINARY_DIR}/scripts/systemd")
file(COPY "${PROJECT_SOURCE_DIR}/scripts/systemd/falco-kmod.service"
		DESTINATION "${PROJECT_BINARY_DIR}/scripts/systemd")
file(COPY "${PROJECT_SOURCE_DIR}/scripts/systemd/falco-bpf.service"
		DESTINATION "${PROJECT_BINARY_DIR}/scripts/systemd")
file(COPY "${PROJECT_SOURCE_DIR}/scripts/systemd/falco-modern-bpf.service"
		DESTINATION "${PROJECT_BINARY_DIR}/scripts/systemd")
file(COPY "${PROJECT_SOURCE_DIR}/scripts/systemd/falco-plugin.service"
		DESTINATION "${PROJECT_BINARY_DIR}/scripts/systemd")
file(COPY "${PROJECT_SOURCE_DIR}/scripts/systemd/falcoctl.service"
		DESTINATION "${PROJECT_BINARY_DIR}/scripts/systemd")

# Debian
configure_file(debian/postinst.in debian/postinst)
configure_file(debian/postrm.in debian/postrm)
configure_file(debian/prerm.in debian/prerm)

# Rpm
configure_file(rpm/postinstall.in rpm/postinstall)
configure_file(rpm/postuninstall.in rpm/postuninstall)
configure_file(rpm/preuninstall.in rpm/preuninstall)

configure_file(falco-driver-loader falco-driver-loader @ONLY)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	install(PROGRAMS ${PROJECT_BINARY_DIR}/scripts/falco-driver-loader
		DESTINATION ${FALCO_BIN_DIR} COMPONENT "${FALCO_COMPONENT_NAME}")
endif()
