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

#
# cpp-httplib (https://github.com/yhirose/cpp-httplib)
#

option(USE_BUNDLED_CPPHTTPLIB "Enable building of the bundled cpp-httplib" ${USE_BUNDLED_DEPS})

if(CPPHTTPLIB_INCLUDE)
    # we already have cpp-httplib
elseif(NOT USE_BUNDLED_CPPHTTPLIB)
    find_package(httplib CONFIG REQUIRED)
    get_target_property(CPPHTTPLIB_INCLUDE httplib::httplib INTERFACE_INCLUDE_DIRECTORIES)
else()
    set(CPPHTTPLIB_SRC "${PROJECT_BINARY_DIR}/cpp-httplib-prefix/src/cpp-httplib")
    set(CPPHTTPLIB_INCLUDE "${CPPHTTPLIB_SRC}")

    message(STATUS "Using bundled cpp-httplib in ${CPPHTTPLIB_SRC}")

    ExternalProject_Add(cpp-httplib
        PREFIX "${PROJECT_BINARY_DIR}/cpp-httplib-prefix"
        URL "https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.13.1.tar.gz"
        URL_HASH "SHA256=9b837d290b61e3f0c4239da0b23bbf14c382922e2bf2a9bac21c1e3feabe1ff9"
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND "")	
endif()

if(NOT TARGET cpp-httplib)
	add_custom_target(cpp-httplib)
endif()