#
# Copyright (C) 2022 The Falco Authors.
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

#
# cpp-httplib (https://github.com/yhirose/cpp-httplib)
#
if(CPPHTTPLIB_INCLUDE)
	# we already have cpp-httplib
else()
	set(CPPHTTPLIB_SRC "${PROJECT_BINARY_DIR}/cpp-httplib-prefix/src/cpp-httplib")
	set(CPPHTTPLIB_INCLUDE "${CPPHTTPLIB_SRC}")

	message(STATUS "Using bundled cpp-httplib in '${CPPHTTPLIB_SRC}'")

	ExternalProject_Add(cpp-httplib
		PREFIX "${PROJECT_BINARY_DIR}/cpp-httplib-prefix"
		URL "https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.10.4.tar.gz"
		URL_HASH "SHA256=7719ff9f309c807dd8a574048764836b6a12bcb7d6ae9e129e7e4289cfdb4bd4"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ""
		INSTALL_COMMAND "")	
endif()
