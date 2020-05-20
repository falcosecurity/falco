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

project(falco)

option(USE_BUNDLED_DEPS "Bundle hard to find dependencies into the Falco binary" OFF)
option(BUILD_WARNINGS_AS_ERRORS "Enable building with -Wextra -Werror flags" OFF)

# Elapsed time
# set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CMAKE_COMMAND} -E time") # TODO(fntlnz, leodido): add a flag to enable this

# Make flag for parallel processing
include(ProcessorCount)
processorcount(PROCESSOR_COUNT)
if(NOT PROCESSOR_COUNT EQUAL 0)
  set(PROCESSOUR_COUNT_MAKE_FLAG -j${PROCESSOR_COUNT})
endif()

# Custom CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

# GNU standard installation directories' definitions
include(GNUInstallDirs)

if(NOT DEFINED FALCO_ETC_DIR)
  set(FALCO_ETC_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/falco")
endif()

if(NOT DRAIOS_DEBUG_FLAGS)
  set(DRAIOS_DEBUG_FLAGS "-D_DEBUG")
endif()

string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE)
if(CMAKE_BUILD_TYPE STREQUAL "debug")
  set(KBUILD_FLAGS "${DRAIOS_DEBUG_FLAGS} ${DRAIOS_FEATURE_FLAGS}")
else()
  set(CMAKE_BUILD_TYPE "release")
  set(KBUILD_FLAGS "${DRAIOS_FEATURE_FLAGS}")
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_COMMON_FLAGS "-Wall -ggdb ${DRAIOS_FEATURE_FLAGS}")

if(BUILD_WARNINGS_AS_ERRORS)
  set(CMAKE_SUPPRESSED_WARNINGS
      "-Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set-variable -Wno-missing-field-initializers -Wno-sign-compare -Wno-type-limits -Wno-implicit-fallthrough -Wno-format-truncation -Wno-stringop-truncation -Wno-stringop-overflow -Wno-restrict"
  )
  set(CMAKE_COMMON_FLAGS "${CMAKE_COMMON_FLAGS} -Wextra -Werror ${CMAKE_SUPPRESSED_WARNINGS}")
endif()

set(CMAKE_C_FLAGS "${CMAKE_COMMON_FLAGS}")
set(CMAKE_CXX_FLAGS "--std=c++0x ${CMAKE_COMMON_FLAGS} -Wno-class-memaccess")

set(CMAKE_C_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")

set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

include(GetFalcoVersion)

set(PACKAGE_NAME "falco")
set(PROBE_NAME "falco")
set(PROBE_DEVICE_NAME "falco")
set(DRIVERS_REPO "https://dl.bintray.com/falcosecurity/driver")
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX
      /usr
      CACHE PATH "Default install path" FORCE)
endif()

set(CMD_MAKE make)

include(ExternalProject)

# jq
include(jq)

# nlohmann-json
set(NJSON_SRC "${PROJECT_BINARY_DIR}/njson-prefix/src/njson")
message(STATUS "Using bundled nlohmann-json in '${NJSON_SRC}'")
set(NJSON_INCLUDE "${NJSON_SRC}/single_include")
ExternalProject_Add(
  njson
  URL "https://s3.amazonaws.com/download.draios.com/dependencies/njson-3.3.0.tar.gz"
  URL_HASH "SHA256=2fd1d207b4669a7843296c41d3b6ac5b23d00dec48dba507ba051d14564aa801"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

# curses
# We pull this in because libsinsp won't build without it
set(CURSES_NEED_NCURSES TRUE)
find_package(Curses REQUIRED)
message(STATUS "Found ncurses: include: ${CURSES_INCLUDE_DIR}, lib: ${CURSES_LIBRARIES}")

# libb64
set(B64_SRC "${PROJECT_BINARY_DIR}/b64-prefix/src/b64")
message(STATUS "Using bundled b64 in '${B64_SRC}'")
set(B64_INCLUDE "${B64_SRC}/include")
set(B64_LIB "${B64_SRC}/src/libb64.a")
ExternalProject_Add(
  b64
  URL "https://s3.amazonaws.com/download.draios.com/dependencies/libb64-1.2.src.zip"
  URL_HASH "SHA256=343d8d61c5cbe3d3407394f16a5390c06f8ff907bd8d614c16546310b689bfd3"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ${CMD_MAKE}
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND "")

# yaml-cpp
include(yaml-cpp)

# OpenSSL
include(OpenSSL)

# libcurl
include(cURL)

# LuaJIT
set(LUAJIT_SRC "${PROJECT_BINARY_DIR}/luajit-prefix/src/luajit/src")
message(STATUS "Using bundled LuaJIT in '${LUAJIT_SRC}'")
set(LUAJIT_INCLUDE "${LUAJIT_SRC}")
set(LUAJIT_LIB "${LUAJIT_SRC}/libluajit.a")
if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "ppc64le")
  ExternalProject_Add(
    luajit
    GIT_REPOSITORY "https://github.com/moonjit/moonjit"
    GIT_TAG "2.1.2"
    PATCH_COMMAND sed -i "s/luaL_reg/luaL_Reg/g" ${PROJECT_SOURCE_DIR}/userspace/engine/formats.cpp && sed -i "s/luaL_reg/luaL_Reg/g" ${PROJECT_SOURCE_DIR}/userspace/engine/rules.cpp && sed -i "s/luaL_reg/luaL_Reg/g" ${PROJECT_SOURCE_DIR}/userspace/falco/falco_outputs.cpp && sed -i "s/luaL_reg/luaL_Reg/g" ${PROJECT_SOURCE_DIR}/userspace/falco/logger.cpp
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${CMD_MAKE}
    BUILD_IN_SOURCE 1
    INSTALL_COMMAND "")
else()
  ExternalProject_Add(
    luajit
    URL "https://s3.amazonaws.com/download.draios.com/dependencies/LuaJIT-2.0.3.tar.gz"
    URL_MD5 "f14e9104be513913810cd59c8c658dc0"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${CMD_MAKE}
    BUILD_IN_SOURCE 1
    INSTALL_COMMAND "")
endif()
# Lpeg
set(LPEG_SRC "${PROJECT_BINARY_DIR}/lpeg-prefix/src/lpeg")
set(LPEG_LIB "${PROJECT_BINARY_DIR}/lpeg-prefix/src/lpeg/build/lpeg.a")
message(STATUS "Using bundled lpeg in '${LPEG_SRC}'")
set(LPEG_DEPENDENCIES "")
list(APPEND LPEG_DEPENDENCIES "luajit")
ExternalProject_Add(
  lpeg
  DEPENDS ${LPEG_DEPENDENCIES}
  URL "https://s3.amazonaws.com/download.draios.com/dependencies/lpeg-1.0.0.tar.gz"
  URL_HASH "SHA256=10190ae758a22a16415429a9eb70344cf29cbda738a6962a9f94a732340abf8e"
  BUILD_COMMAND LUA_INCLUDE=${LUAJIT_INCLUDE} "${PROJECT_SOURCE_DIR}/scripts/build-lpeg.sh" "${LPEG_SRC}/build"
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND ""
  INSTALL_COMMAND "")

# libyaml
find_library(LIBYAML_LIB NAMES libyaml.so)
if(LIBYAML_LIB)
  message(STATUS "Found libyaml: lib: ${LIBYAML_LIB}")
else()
  message(FATAL_ERROR "Couldn't find system libyaml")
endif()

# lyaml
set(LYAML_SRC "${PROJECT_BINARY_DIR}/lyaml-prefix/src/lyaml/ext/yaml")
set(LYAML_LIB "${LYAML_SRC}/.libs/yaml.a")
message(STATUS "Using bundled lyaml in '${LYAML_SRC}'")
set(LYAML_DEPENDENCIES "")
list(APPEND LYAML_DEPENDENCIES "luajit")
ExternalProject_Add(
  lyaml
  DEPENDS ${LYAML_DEPENDENCIES}
  URL "https://s3.amazonaws.com/download.draios.com/dependencies/lyaml-release-v6.0.tar.gz"
  URL_HASH "SHA256=9d7cf74d776999ff6f758c569d5202ff5da1f303c6f4229d3b41f71cd3a3e7a7"
  BUILD_COMMAND ${CMD_MAKE}
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND ./configure --enable-static LIBS=-lyaml LUA_INCLUDE=-I${LUAJIT_INCLUDE} LUA=${LUAJIT_SRC}/luajit
  INSTALL_COMMAND sh -c
                  "cp -R ${PROJECT_BINARY_DIR}/lyaml-prefix/src/lyaml/lib/* ${PROJECT_SOURCE_DIR}/userspace/engine/lua")

# One TBB
set(TBB_SRC "${PROJECT_BINARY_DIR}/tbb-prefix/src/tbb")

message(STATUS "Using bundled tbb in '${TBB_SRC}'")

set(TBB_INCLUDE_DIR "${TBB_SRC}/include/")
set(TBB_LIB "${TBB_SRC}/build/lib_release/libtbb.a")
ExternalProject_Add(
  tbb
  URL "https://github.com/oneapi-src/oneTBB/archive/2018_U5.tar.gz"
  URL_HASH "SHA256=b8dbab5aea2b70cf07844f86fa413e549e099aa3205b6a04059ca92ead93a372"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ${CMD_MAKE} tbb_build_dir=${TBB_SRC}/build tbb_build_prefix=lib extra_inc=big_iron.inc
  BUILD_IN_SOURCE 1
  BUILD_BYPRODUCTS ${TBB_LIB}
  INSTALL_COMMAND "")

# civetweb
set(CIVETWEB_SRC "${PROJECT_BINARY_DIR}/civetweb-prefix/src/civetweb/")
set(CIVETWEB_LIB "${CIVETWEB_SRC}/install/lib/libcivetweb.a")
set(CIVETWEB_INCLUDE_DIR "${CIVETWEB_SRC}/install/include")
message(STATUS "Using bundled civetweb in '${CIVETWEB_SRC}'")
ExternalProject_Add(
  civetweb
  URL "https://github.com/civetweb/civetweb/archive/v1.11.tar.gz"
  URL_HASH "SHA256=de7d5e7a2d9551d325898c71e41d437d5f7b51e754b242af897f7be96e713a42"
  CONFIGURE_COMMAND ${CMAKE_COMMAND} -E make_directory ${CIVETWEB_SRC}/install/lib
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CIVETWEB_SRC}/install/include
  BUILD_IN_SOURCE 1
  BUILD_COMMAND ${CMD_MAKE} COPT="-DNO_FILES" WITH_CPP=1
  INSTALL_COMMAND ${CMD_MAKE} COPT="-DNO_FILES" install-lib install-headers PREFIX=${CIVETWEB_SRC}/install "WITH_CPP=1")

#string-view-lite
include(DownloadStringViewLite)

# gRPC
include(gRPC)

# sysdig
include(sysdig)

# Installation
install(FILES falco.yaml DESTINATION "${FALCO_ETC_DIR}")

# Coverage
include(Coverage)

# Tests
add_subdirectory(test)

# Rules
add_subdirectory(rules)

# Dockerfiles
add_subdirectory(docker)

# Clang format
# add_custom_target(format COMMAND clang-format --style=file -i $<TARGET_PROPERTY:falco,SOURCES> COMMENT "Formatting ..." VERBATIM)

# Shared build variables
set(FALCO_SINSP_LIBRARY sinsp)
set(FALCO_SHARE_DIR share/falco)
set(FALCO_ABSOLUTE_SHARE_DIR "${CMAKE_INSTALL_PREFIX}/${FALCO_SHARE_DIR}")
set(FALCO_BIN_DIR bin)

add_subdirectory(scripts)
add_subdirectory(userspace/engine)
add_subdirectory(userspace/falco)
add_subdirectory(tests)

# Packages configuration
include(CPackConfig)
