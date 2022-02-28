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
option(MINIMAL_BUILD "Build a minimal version of Falco, containing only the engine and basic input/output (EXPERIMENTAL)" OFF)
option(MUSL_OPTIMIZED_BUILD "Enable if you want a musl optimized build" OFF)

# We shouldn't need to set this, see https://gitlab.kitware.com/cmake/cmake/-/issues/16419
option(EP_UPDATE_DISCONNECTED "ExternalProject update disconnected" OFF)
if (${EP_UPDATE_DISCONNECTED})
  set_property(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    PROPERTY EP_UPDATE_DISCONNECTED TRUE)
endif()


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
  add_definitions(-DBUILD_TYPE_RELEASE)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

if(MINIMAL_BUILD)
  set(MINIMAL_BUILD_FLAGS "-DMINIMAL_BUILD")
endif()

if(MUSL_OPTIMIZED_BUILD)
  set(MUSL_FLAGS "-static -Os -fPIE -pie")
  add_definitions(-DMUSL_OPTIMIZED)
endif()

# explicitly set hardening flags
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(FALCO_SECURITY_FLAGS "-Wl,-z,relro,-z,now -fstack-protector-strong")
if(CMAKE_BUILD_TYPE STREQUAL "release")
  set(FALCO_SECURITY_FLAGS "${FALCO_SECURITY_FLAGS} -D_FORTIFY_SOURCE=2")
endif()

set(CMAKE_COMMON_FLAGS "${FALCO_SECURITY_FLAGS} -Wall -ggdb ${DRAIOS_FEATURE_FLAGS} ${MINIMAL_BUILD_FLAGS} ${MUSL_FLAGS}")

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
set(DRIVER_NAME "falco")
set(DRIVER_DEVICE_NAME "falco")
set(DRIVERS_REPO "https://download.falco.org/driver")
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX
      /usr
      CACHE PATH "Default install path" FORCE)
endif()

set(CMD_MAKE make)

include(ExternalProject)

# libs
include(falcosecurity-libs)

# LuaJit provided by libs
include(luajit)

# jq
include(jq)

# nlohmann-json
set(NJSON_SRC "${PROJECT_BINARY_DIR}/njson-prefix/src/njson")
message(STATUS "Using bundled nlohmann-json in '${NJSON_SRC}'")
set(NJSON_INCLUDE "${NJSON_SRC}/single_include")
ExternalProject_Add(
  njson
  URL "https://github.com/nlohmann/json/archive/v3.3.0.tar.gz"
  URL_HASH "SHA256=2fd1d207b4669a7843296c41d3b6ac5b23d00dec48dba507ba051d14564aa801"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

# b64
include(b64)

# yaml-cpp
include(yaml-cpp)

if(NOT MINIMAL_BUILD)
  # OpenSSL
  include(openssl)

  # libcurl
  include(curl)

  # civetweb
  include(civetweb)
endif()

include(cxxopts)

# libyaml
include(libyaml)

# lyaml
include(lyaml)

# One TBB
include(tbb)

#string-view-lite
include(DownloadStringViewLite)

if(NOT MINIMAL_BUILD)
  include(zlib)
  include(cares)
  include(protobuf)
  # gRPC
  include(grpc)
endif()

# Installation
install(FILES falco.yaml DESTINATION "${FALCO_ETC_DIR}")

if(NOT MINIMAL_BUILD)
  # Coverage
  include(Coverage)

  # Tests
  add_subdirectory(test)
endif()

# Rules
add_subdirectory(rules)

# Dockerfiles
add_subdirectory(docker)

# Clang format
# add_custom_target(format COMMAND clang-format --style=file -i $<TARGET_PROPERTY:falco,SOURCES> COMMENT "Formatting ..." VERBATIM)

# Static analysis
include(static-analysis)

# Shared build variables
set(FALCO_SINSP_LIBRARY sinsp)
set(FALCO_SHARE_DIR share/falco)
set(FALCO_PLUGINS_DIR ${FALCO_SHARE_DIR}/plugins)
set(FALCO_ABSOLUTE_SHARE_DIR "${CMAKE_INSTALL_PREFIX}/${FALCO_SHARE_DIR}")
set(FALCO_BIN_DIR bin)

add_subdirectory(scripts)
add_subdirectory(userspace/engine)
add_subdirectory(userspace/falco)
add_subdirectory(tests)

if(NOT MUSL_OPTIMIZED_BUILD)
  include(plugins)
endif()

# Packages configuration
include(CPackConfig)
