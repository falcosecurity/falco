#
# Copyright (C) 2019 The Falco Authors.
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
cmake_minimum_required(VERSION 3.5.1)

project(sysdig-repo NONE)

include(ExternalProject)
message(STATUS "Driver version: ${SYSDIG_VERSION}")

if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
    ExternalProject_Add(
    sysdig
    URL "https://github.com/draios/sysdig/archive/${SYSDIG_VERSION}.tar.gz"
    URL_HASH "${SYSDIG_CHECKSUM}"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    TEST_COMMAND ""
    PATCH_COMMAND patch -p1 -i ${CMAKE_CURRENT_SOURCE_DIR}/patch/libscap.patch)
elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "ppc64le")
    set(SYSDIG_SOURCE_DIR "${CMAKE_BINARY_DIR}/sysdig-prefix/src/sysdig")
    ExternalProject_Add(
    sysdig
    URL "https://github.com/draios/sysdig/archive/${SYSDIG_VERSION}.tar.gz"
    # URL_HASH SHA256=bd09607aa8beb863db07e695863f7dc543e2d39e7153005759d26a340ff66fa5
    # we need to change the case of the luaL_reg to luaL_Reg since we are using Moonjit
    PATCH_COMMAND sed -i "s/luaL_reg/luaL_Reg/g" ${SYSDIG_SOURCE_DIR}/userspace/libsinsp/chisel.cpp && sed -i "s/luaL_reg/luaL_Reg/g" ${SYSDIG_SOURCE_DIR}/userspace/libsinsp/lua_parser.cpp && sed -i "s/luaL_getn/lua_objlen /g" ${SYSDIG_SOURCE_DIR}/userspace/libsinsp/lua_parser_api.cpp
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    TEST_COMMAND "")
endif()
