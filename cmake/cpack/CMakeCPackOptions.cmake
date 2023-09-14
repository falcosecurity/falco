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

if(CPACK_GENERATOR MATCHES "DEB" OR CPACK_GENERATOR MATCHES "RPM")
	list(APPEND CPACK_INSTALL_COMMANDS "mkdir -p _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/systemd/falco-kmod-inject.service _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/systemd/falco-kmod.service _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/systemd/falco-bpf.service _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/systemd/falco-modern-bpf.service _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/systemd/falco-custom.service _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/systemd/falcoctl-artifact-follow.service _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
endif()

if(CPACK_GENERATOR MATCHES "TGZ")
	set(CPACK_SET_DESTDIR "ON")
endif()
