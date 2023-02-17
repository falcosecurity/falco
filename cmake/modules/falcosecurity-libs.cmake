#
# Copyright (C) 2021 The Falco Authors.
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

set(FALCOSECURITY_LIBS_CMAKE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/falcosecurity-libs-repo")
set(FALCOSECURITY_LIBS_CMAKE_WORKING_DIR "${CMAKE_BINARY_DIR}/falcosecurity-libs-repo")

file(MAKE_DIRECTORY ${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR})

# explicitly disable the bundled driver, since we pull it separately
set(USE_BUNDLED_DRIVER OFF CACHE BOOL "")

if(FALCOSECURITY_LIBS_SOURCE_DIR)
  set(FALCOSECURITY_LIBS_VERSION "0.0.0-local")
  message(STATUS "Using local version of falcosecurity/libs: '${FALCOSECURITY_LIBS_SOURCE_DIR}'")
else()
  # FALCOSECURITY_LIBS_VERSION accepts a git reference (branch name, commit hash, or tag) to the falcosecurity/libs repository.
  # In case you want to test against another falcosecurity/libs version (or branch, or commit) just pass the variable -
  # ie., `cmake -DFALCOSECURITY_LIBS_VERSION=dev ..`
  if(NOT FALCOSECURITY_LIBS_VERSION)
    set(FALCOSECURITY_LIBS_VERSION "8a8d2389e4eea9e89efef9e3b06a70aa2a0bf5d0")
    set(FALCOSECURITY_LIBS_CHECKSUM "SHA256=b8cd2827a10a26837f05b212734051c769a3e4d9d615acc411fd3966ed4ec6ab")
  endif()

  # cd /path/to/build && cmake /path/to/source
  execute_process(COMMAND "${CMAKE_COMMAND}" -DFALCOSECURITY_LIBS_VERSION=${FALCOSECURITY_LIBS_VERSION} -DFALCOSECURITY_LIBS_CHECKSUM=${FALCOSECURITY_LIBS_CHECKSUM}
    ${FALCOSECURITY_LIBS_CMAKE_SOURCE_DIR} WORKING_DIRECTORY ${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR})

  # cmake --build .
  execute_process(COMMAND "${CMAKE_COMMAND}" --build . WORKING_DIRECTORY "${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR}")
  set(FALCOSECURITY_LIBS_SOURCE_DIR "${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR}/falcosecurity-libs-prefix/src/falcosecurity-libs")
endif()

set(LIBS_PACKAGE_NAME "falcosecurity")

add_definitions(-D_GNU_SOURCE)
add_definitions(-DHAS_CAPTURE)

if(MUSL_OPTIMIZED_BUILD)
  add_definitions(-DMUSL_OPTIMIZED)
endif()

set(SCAP_HOST_ROOT_ENV_VAR_NAME "HOST_ROOT")

if(NOT LIBSCAP_DIR)
  set(LIBSCAP_DIR "${FALCOSECURITY_LIBS_SOURCE_DIR}")
endif()

set(LIBSINSP_DIR "${FALCOSECURITY_LIBS_SOURCE_DIR}")

# configure gVisor support
set(BUILD_LIBSCAP_GVISOR ${BUILD_FALCO_GVISOR} CACHE BOOL "")

# configure modern BPF support
set(BUILD_LIBSCAP_MODERN_BPF ${BUILD_FALCO_MODERN_BPF} CACHE BOOL "")

# explicitly disable the tests/examples of this dependency
set(CREATE_TEST_TARGETS OFF CACHE BOOL "")
set(BUILD_LIBSCAP_EXAMPLES OFF CACHE BOOL "")

set(USE_BUNDLED_TBB ON CACHE BOOL "")
set(USE_BUNDLED_B64 ON CACHE BOOL "")
set(USE_BUNDLED_JSONCPP ON CACHE BOOL "")
set(USE_BUNDLED_VALIJSON ON CACHE BOOL "")
set(USE_BUNDLED_RE2 ON CACHE BOOL "")

list(APPEND CMAKE_MODULE_PATH "${FALCOSECURITY_LIBS_SOURCE_DIR}/cmake/modules")

include(CheckSymbolExists)
check_symbol_exists(strlcpy "string.h" HAVE_STRLCPY)

if(HAVE_STRLCPY)
  message(STATUS "Existing strlcpy found, will *not* use local definition by setting -DHAVE_STRLCPY.")
  add_definitions(-DHAVE_STRLCPY)
else()
  message(STATUS "No strlcpy found, will use local definition")
endif()

include(driver)
include(libscap)
include(libsinsp)
