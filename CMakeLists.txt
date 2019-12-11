#
# Copyright (C) 2019 The Falco Authors.
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
cmake_minimum_required(VERSION 3.3.2)

project(falco)

if(NOT SYSDIG_DIR)
  get_filename_component(SYSDIG_DIR "${PROJECT_SOURCE_DIR}/../sysdig" REALPATH)
endif()

# Custom CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")
list(APPEND CMAKE_MODULE_PATH "${SYSDIG_DIR}/cmake/modules")

option(BUILD_WARNINGS_AS_ERRORS "Enable building with -Wextra -Werror flags")

if(NOT DEFINED FALCO_ETC_DIR)
	set(FALCO_ETC_DIR "/etc/falco")
endif()

if(NOT DRAIOS_DEBUG_FLAGS)
	set(DRAIOS_DEBUG_FLAGS "-D_DEBUG")
endif()

string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE)
if (CMAKE_BUILD_TYPE STREQUAL "debug")
	set(KBUILD_FLAGS "${DRAIOS_DEBUG_FLAGS} ${DRAIOS_FEATURE_FLAGS}")
else()
	set(CMAKE_BUILD_TYPE "release")
	set(KBUILD_FLAGS "${DRAIOS_FEATURE_FLAGS}")
endif()

set(CMAKE_COMMON_FLAGS "-Wall -ggdb ${DRAIOS_FEATURE_FLAGS}")

if(BUILD_WARNINGS_AS_ERRORS)
	set(CMAKE_SUPPRESSED_WARNINGS "-Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set-variable -Wno-missing-field-initializers -Wno-sign-compare -Wno-type-limits -Wno-implicit-fallthrough -Wno-format-truncation")
	set(CMAKE_COMMON_FLAGS "${CMAKE_COMMON_FLAGS} -Wextra -Werror ${CMAKE_SUPPRESSED_WARNINGS}")
endif()

set(CMAKE_C_FLAGS "${CMAKE_COMMON_FLAGS}")
set(CMAKE_CXX_FLAGS "--std=c++0x ${CMAKE_COMMON_FLAGS}")

set(CMAKE_C_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")

set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")
add_definitions(-DK8S_DISABLE_THREAD)
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	add_definitions(-DHAS_CAPTURE)
endif()

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
    string(REGEX
           REPLACE "^v([0-9]+)(\\.[0-9]+)(\\.[0-9]+)?"
                   "\\1\\2\\3"
                   FALCO_VERSION
                   ${FALCO_VERSION})
  endif()
endif()
message(STATUS "Falco version: ${FALCO_VERSION}")

set(PACKAGE_NAME "falco")
set(PROBE_VERSION "${FALCO_VERSION}")
set(PROBE_NAME "falco-probe")
set(PROBE_DEVICE_NAME "falco")
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX /usr CACHE PATH "Default install path" FORCE)
endif()

set(CMD_MAKE make)

include(ExternalProject)

# zlib
find_path(ZLIB_INCLUDE zlib.h PATH_SUFFIXES zlib)
find_library(ZLIB_LIB NAMES z)
if(ZLIB_INCLUDE AND ZLIB_LIB)
	message(STATUS "Found zlib: include: ${ZLIB_INCLUDE}, lib: ${ZLIB_LIB}")
else()
	message(FATAL_ERROR "Couldn't find system zlib")
endif()

# jq
find_path(JQ_INCLUDE jq.h PATH_SUFFIXES jq)
find_library(JQ_LIB NAMES jq)
if(JQ_INCLUDE AND JQ_LIB)
	message(STATUS "Found jq: include: ${JQ_INCLUDE}, lib: ${JQ_LIB}")
else()
	message(FATAL_ERROR "Couldn't find system jq")
endif()

set(JSONCPP_SRC "${SYSDIG_DIR}/userspace/libsinsp/third-party/jsoncpp")
set(JSONCPP_INCLUDE "${JSONCPP_SRC}")
set(JSONCPP_LIB_SRC "${JSONCPP_SRC}/jsoncpp.cpp")

# nlohmann-json
set(NJSON_SRC "${PROJECT_BINARY_DIR}/njson-prefix/src/njson")
message(STATUS "Using bundled nlohmann-json in '${NJSON_SRC}'")
set(NJSON_INCLUDE "${NJSON_SRC}/single_include")
ExternalProject_Add(njson
	URL "https://s3.amazonaws.com/download.draios.com/dependencies/njson-3.3.0.tar.gz"
	URL_MD5 "e26760e848656a5da400662e6c5d999a"
	CONFIGURE_COMMAND ""
	BUILD_COMMAND ""
	INSTALL_COMMAND "")

# curses
# we pull this in because libsinsp won't build without it
set(CURSES_NEED_NCURSES TRUE)
find_package(Curses REQUIRED)
message(STATUS "Found ncurses: include: ${CURSES_INCLUDE_DIR}, lib: ${CURSES_LIBRARIES}")


# libb64
set(B64_SRC "${PROJECT_BINARY_DIR}/b64-prefix/src/b64")
message(STATUS "Using bundled b64 in '${B64_SRC}'")
set(B64_INCLUDE "${B64_SRC}/include")
set(B64_LIB "${B64_SRC}/src/libb64.a")
ExternalProject_Add(b64
	URL "https://s3.amazonaws.com/download.draios.com/dependencies/libb64-1.2.src.zip"
	URL_MD5 "a609809408327117e2c643bed91b76c5"
	CONFIGURE_COMMAND ""
	BUILD_COMMAND ${CMD_MAKE}
	BUILD_IN_SOURCE 1
	INSTALL_COMMAND "")

# yamlcpp
find_path(YAMLCPP_INCLUDE_DIR NAMES yaml-cpp/yaml.h)
find_library(YAMLCPP_LIB NAMES yaml-cpp)
if(YAMLCPP_INCLUDE_DIR AND YAMLCPP_LIB)
	message(STATUS "Found yamlcpp: include: ${YAMLCPP_INCLUDE_DIR}, lib: ${YAMLCPP_LIB}")
else()
	message(FATAL_ERROR "Couldn't find system yamlcpp")
endif()

# OpenSSL
find_package(OpenSSL REQUIRED)
message(STATUS "Found OpenSSL: include: ${OPENSSL_INCLUDE_DIR}, lib: ${OPENSSL_LIBRARIES}")

find_program (OPENSSL_BINARY openssl)
if(NOT OPENSSL_BINARY)
	message(FATAL_ERROR "Couldn't find the openssl command line in PATH")
else()
	message(STATUS "Found openssl binary: ${OPENSSL_BINARY}")
endif()

# libcurl
find_package(CURL REQUIRED)
message(STATUS "Found CURL: include: ${CURL_INCLUDE_DIR}, lib: ${CURL_LIBRARIES}")

# LuaJIT
set(LUAJIT_SRC "${PROJECT_BINARY_DIR}/luajit-prefix/src/luajit/src")
message(STATUS "Using bundled LuaJIT in '${LUAJIT_SRC}'")
set(LUAJIT_INCLUDE "${LUAJIT_SRC}")
set(LUAJIT_LIB "${LUAJIT_SRC}/libluajit.a")
ExternalProject_Add(luajit
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

ExternalProject_Add(lpeg
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

ExternalProject_Add(lyaml
	DEPENDS ${LYAML_DEPENDENCIES}
	URL "https://s3.amazonaws.com/download.draios.com/dependencies/lyaml-release-v6.0.tar.gz"
	URL_MD5 "dc3494689a0dce7cf44e7a99c72b1f30"
	BUILD_COMMAND ${CMD_MAKE}
	BUILD_IN_SOURCE 1
	CONFIGURE_COMMAND ./configure --enable-static LIBS=-lyaml LUA_INCLUDE=-I${LUAJIT_INCLUDE} LUA=${LUAJIT_SRC}/luajit
	INSTALL_COMMAND sh -c "cp -R ${PROJECT_BINARY_DIR}/lyaml-prefix/src/lyaml/lib/* ${PROJECT_SOURCE_DIR}/userspace/engine/lua")


# Intel TBB
set(TBB_SRC "${PROJECT_BINARY_DIR}/tbb-prefix/src/tbb")

message(STATUS "Using bundled tbb in '${TBB_SRC}'")

set(TBB_INCLUDE_DIR "${TBB_SRC}/include/")
set(TBB_LIB "${TBB_SRC}/build/lib_release/libtbb.a")
ExternalProject_Add(tbb
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

ExternalProject_Add(civetweb
	URL "https://github.com/civetweb/civetweb/archive/v1.11.tar.gz"
			URL_MD5 "b6d2175650a27924bccb747cbe084cd4"
	CONFIGURE_COMMAND ${CMAKE_COMMAND} -E make_directory ${CIVETWEB_SRC}/install/lib
				COMMAND ${CMAKE_COMMAND} -E make_directory ${CIVETWEB_SRC}/install/include
			BUILD_IN_SOURCE 1
			BUILD_COMMAND ${CMD_MAKE} COPT="-DNO_FILES" WITH_CPP=1
	INSTALL_COMMAND ${CMD_MAKE} install-lib install-headers PREFIX=${CIVETWEB_SRC}/install "WITH_CPP=1 OPENSSL_API_1_1")

# c-ares
find_path(CARES_INCLUDE NAMES ares.h)
find_library(CARES_LIB NAMES libcares.so)
if(CARES_INCLUDE AND CARES_LIB)
	message(STATUS "Found c-ares: include: ${CARES_INCLUDE}, lib: ${CARES_LIB}")
else()
	message(FATAL_ERROR "Couldn't find system c-ares")
endif()


# protobuf
find_program(PROTOC NAMES protoc)
find_path(PROTOBUF_INCLUDE NAMES google/protobuf/message.h)
find_library(PROTOBUF_LIB NAMES libprotobuf.so)
if(PROTOC AND PROTOBUF_INCLUDE AND PROTOBUF_LIB)
	message(STATUS "Found protobuf: compiler: ${PROTOC}, include: ${PROTOBUF_INCLUDE}, lib: ${PROTOBUF_LIB}")
else()
	message(FATAL_ERROR "Couldn't find system protobuf")
endif()

# gRPC
include(FindGRPC)

# Installation
install(FILES falco.yaml
	DESTINATION "${FALCO_ETC_DIR}")

# Tests coverage
option(FALCO_COVERAGE "Build test suite with coverage information" OFF)
if(FALCO_COVERAGE)
    if (NOT (("${CMAKE_CXX_COMPILER_ID}" MATCHES "GNU") OR ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")))
        message(FATAL_ERROR "FALCO_COVERAGE requires GCC or Clang.")
    endif()

    message(STATUS "Building with coverage information")
    add_compile_options(-g --coverage)
    set(CMAKE_SHARED_LINKER_FLAGS "--coverage ${CMAKE_SHARED_LINKER_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "--coverage ${CMAKE_EXE_LINKER_FLAGS}")
endif()


# Tests
add_subdirectory(test)

# Rules
add_subdirectory(rules)

# Dockerfiles
add_subdirectory(docker)

# Driver
add_subdirectory("${SYSDIG_DIR}/driver" "${PROJECT_BINARY_DIR}/driver")
include(FindMakedev)

# libscap
add_subdirectory("${SYSDIG_DIR}/userspace/libscap" "${PROJECT_BINARY_DIR}/userspace/libscap")

# libsinsp
add_subdirectory("${SYSDIG_DIR}/userspace/libsinsp" "${PROJECT_BINARY_DIR}/userspace/libsinsp")

# shared build variables
set(FALCO_SINSP_LIBRARY sinsp)
set(FALCO_SHARE_DIR share/falco)
set(FALCO_ABSOLUTE_SHARE_DIR "${CMAKE_INSTALL_PREFIX}/${FALCO_SHARE_DIR}")
set(FALCO_BIN_DIR bin)

add_subdirectory(scripts)
add_subdirectory(userspace/engine)
add_subdirectory(userspace/falco)
add_subdirectory(tests)

# packages configuration
include(CPackConfig)
