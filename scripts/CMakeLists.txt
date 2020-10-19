#
# Copyright (C) 2020 The Falco Authors.
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

configure_file(debian/postinst.in debian/postinst)
configure_file(debian/postrm.in debian/postrm)
configure_file(debian/prerm.in debian/prerm)

file(COPY "${PROJECT_SOURCE_DIR}/scripts/debian/falco.service"
	DESTINATION "${PROJECT_BINARY_DIR}/scripts/debian")

configure_file(rpm/postinstall.in rpm/postinstall)
configure_file(rpm/postuninstall.in rpm/postuninstall)
configure_file(rpm/preuninstall.in rpm/preuninstall)

file(COPY "${PROJECT_SOURCE_DIR}/scripts/rpm/falco.service"
	DESTINATION "${PROJECT_BINARY_DIR}/scripts/rpm")

configure_file(falco-driver-loader falco-driver-loader @ONLY)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	install(PROGRAMS ${PROJECT_BINARY_DIR}/scripts/falco-driver-loader
		DESTINATION ${FALCO_BIN_DIR})
endif()
