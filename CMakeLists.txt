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

# Create the falco version variable according to git index
if(NOT FALCO_VERSION)
  include(GetGitRevisionDescription)
  git_get_exact_tag(FALCO_TAG)
  if(NOT FALCO_TAG)
    git_describe(FALCO_VERSION "--always")
    git_local_changes(FALCO_CHANGES)
    if(FALCO_CHANGES STREQUAL "DIRTY")
      string(TOLOWER "${FALCO_CHANGES}" FALCO_CHANGES)
      set(FALCO_VERSION "${FALCO_VERSION}.${FALCO_CHANGES}")
    endif()
    set(FALCO_VERSION "0.${FALCO_VERSION}")
  else()
    set(FALCO_VERSION "${FALCO_TAG}")
    string(REGEX REPLACE "^v([0-9]+)(\\.[0-9]+)(\\.[0-9]+)?" "\\1\\2\\3" FALCO_VERSION ${FALCO_VERSION})
  endif()
endif()
message(STATUS "Falco version: ${FALCO_VERSION}")

set(PACKAGE_NAME "falco")
set(PROBE_VERSION "${FALCO_VERSION}")
set(PROBE_NAME "falco-probe")
set(PROBE_DEVICE_NAME "falco")
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
  URL_MD5 "e26760e848656a5da400662e6c5d999a"
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
  URL_MD5 "a609809408327117e2c643bed91b76c5"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ${CMD_MAKE}
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND "")

# yaml-cpp
include(yaml-cpp)

# OpenSSL
find_package(OpenSSL REQUIRED)
message(STATUS "Found OpenSSL: include: ${OPENSSL_INCLUDE_DIR}, lib: ${OPENSSL_LIBRARIES}")
find_program(OPENSSL_BINARY openssl)
if(NOT OPENSSL_BINARY)
  message(FATAL_ERROR "Couldn't find the openssl command line in PATH")
else()
  message(STATUS "Found openssl binary: ${OPENSSL_BINARY}")
endif()

# libcurl
include(cURL)

# LuaJIT
set(LUAJIT_SRC "${PROJECT_BINARY_DIR}/luajit-prefix/src/luajit/src")
message(STATUS "Using bundled LuaJIT in '${LUAJIT_SRC}'")
set(LUAJIT_INCLUDE "${LUAJIT_SRC}")
set(LUAJIT_LIB "${LUAJIT_SRC}/libluajit.a")
ExternalProject_Add(
  luajit
  URL "https://s3.amazonaws.com/download.draios.com/dependencies/LuaJIT-2.0.3.tar.gz"
  URL_MD5 "f14e9104be513913810cd59c8c658dc0"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ${CMD_MAKE}
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND "")

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
  URL_MD5 "0aec64ccd13996202ad0c099e2877ece"
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
  URL_MD5 "dc3494689a0dce7cf44e7a99c72b1f30"
  BUILD_COMMAND ${CMD_MAKE}
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND ./configure --enable-static LIBS=-lyaml LUA_INCLUDE=-I${LUAJIT_INCLUDE} LUA=${LUAJIT_SRC}/luajit
  INSTALL_COMMAND sh -c
                  "cp -R ${PROJECT_BINARY_DIR}/lyaml-prefix/src/lyaml/lib/* ${PROJECT_SOURCE_DIR}/userspace/engine/lua")

# Intel TBB
set(TBB_SRC "${PROJECT_BINARY_DIR}/tbb-prefix/src/tbb")

message(STATUS "Using bundled tbb in '${TBB_SRC}'")

set(TBB_INCLUDE_DIR "${TBB_SRC}/include/")
set(TBB_LIB "${TBB_SRC}/build/lib_release/libtbb.a")
ExternalProject_Add(
  tbb
  URL "https://github.com/intel/tbb/archive/2018_U5.tar.gz"
  URL_MD5 "ff3ae09f8c23892fbc3008c39f78288f"
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
  URL_MD5 "b6d2175650a27924bccb747cbe084cd4"
  CONFIGURE_COMMAND ${CMAKE_COMMAND} -E make_directory ${CIVETWEB_SRC}/install/lib
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CIVETWEB_SRC}/install/include
  BUILD_IN_SOURCE 1
  BUILD_COMMAND ${CMD_MAKE} COPT="-DNO_FILES" WITH_CPP=1
  INSTALL_COMMAND ${CMD_MAKE} COPT="-DNO_FILES" install-lib install-headers PREFIX=${CIVETWEB_SRC}/install "WITH_CPP=1")

# gRPC
include(gRPC)

# sysdig
include(sysdig)

# Installation
install(FILES falco.yaml DESTINATION "${FALCO_ETC_DIR}")

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
