#
# Copyright (C) 2020 The Falco Authors.
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

set(CPACK_PACKAGE_NAME "${PACKAGE_NAME}")
set(CPACK_PACKAGE_VENDOR "Cloud Native Computing Foundation (CNCF) cncf.io.")
set(CPACK_PACKAGE_CONTACT "cncf-falco-dev@lists.cncf.io") # todo: change this once we've got @falco.org addresses
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Falco - Container Native Runtime Security")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/scripts/description.txt")
set(CPACK_PACKAGE_VERSION "${FALCO_VERSION}")
set(CPACK_PACKAGE_VERSION_MAJOR "${FALCO_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${FALCO_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${FALCO_VERSION_PATCH}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PROJECT_CONFIG_FILE "${PROJECT_SOURCE_DIR}/cmake/cpack/CMakeCPackOptions.cmake")
set(CPACK_STRIP_FILES "ON")
set(CPACK_PACKAGE_RELOCATABLE "OFF")

set(CPACK_GENERATOR DEB RPM TGZ)

set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://www.falco.org")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "dkms (>= 2.1.0.0), libyaml-0-2")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_BINARY_DIR}/scripts/debian/postinst;${CMAKE_BINARY_DIR}/scripts/debian/prerm;${CMAKE_BINARY_DIR}/scripts/debian/postrm;${PROJECT_SOURCE_DIR}/cmake/cpack/debian/conffiles"
)

set(CPACK_RPM_PACKAGE_LICENSE "Apache v2.0")
set(CPACK_RPM_PACKAGE_URL "https://www.falco.org")
set(CPACK_RPM_PACKAGE_REQUIRES "dkms, kernel-devel, libyaml, ncurses")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_BINARY_DIR}/scripts/rpm/postinstall")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${CMAKE_BINARY_DIR}/scripts/rpm/preuninstall")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE "${CMAKE_BINARY_DIR}/scripts/rpm/postuninstall")
set(CPACK_RPM_PACKAGE_VERSION "${FALCO_VERSION}")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
    /usr/src
    /usr/share/man
    /usr/share/man/man8
    /etc
    /usr
    /usr/bin
    /usr/share
    /etc/rc.d
    /etc/rc.d/init.d)
set(CPACK_RPM_PACKAGE_RELOCATABLE "OFF")

include(CPack)
