#
# Copyright (C) 2016-2018 Draios Inc dba Sysdig.
#
# This file is part of falco .
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
if(CPACK_GENERATOR MATCHES "DEB")
	list(APPEND CPACK_INSTALL_COMMANDS "mkdir -p _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/etc/init.d/")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/debian/falco _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/etc/init.d")
endif()

if(CPACK_GENERATOR MATCHES "RPM")
	list(APPEND CPACK_INSTALL_COMMANDS "mkdir -p _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/etc/rc.d/init.d/")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/rpm/falco _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/etc/rc.d/init.d")
endif()

if(CPACK_GENERATOR MATCHES "TGZ")
	set(CPACK_SET_DESTDIR "ON")
	set(CPACK_STRIP_FILES "OFF")
endif()
