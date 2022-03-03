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

if(FALCOSECURITY_LIBS_SOURCE_DIR)
  set(FALCOSECURITY_LIBS_VERSION "local")
  message(STATUS "Using local falcosecurity/libs in '${FALCOSECURITY_LIBS_SOURCE_DIR}'")
else()
  # The falcosecurity/libs git reference (branch name, commit hash, or tag) To update falcosecurity/libs version for the next release, change the
  # default below In case you want to test against another falcosecurity/libs version just pass the variable - ie., `cmake
  # -DFALCOSECURITY_LIBS_VERSION=dev ..`
  if(NOT FALCOSECURITY_LIBS_VERSION)
    set(FALCOSECURITY_LIBS_VERSION "b7eb0dd65226a8dc254d228c8d950d07bf3521d2")
    set(FALCOSECURITY_LIBS_CHECKSUM "SHA256=0f6dcdc3b94243c91294698ee343806539af81c5b33c60c6acf83fc1aa455e85")
  endif()

  # cd /path/to/build && cmake /path/to/source
  execute_process(COMMAND "${CMAKE_COMMAND}" -DFALCOSECURITY_LIBS_VERSION=${FALCOSECURITY_LIBS_VERSION} -DFALCOSECURITY_LIBS_CHECKSUM=${FALCOSECURITY_LIBS_CHECKSUM}
                          ${FALCOSECURITY_LIBS_CMAKE_SOURCE_DIR} WORKING_DIRECTORY ${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR})

  # todo(leodido, fntlnz) > use the following one when CMake version will be >= 3.13

  # execute_process(COMMAND "${CMAKE_COMMAND}" -B ${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR} WORKING_DIRECTORY
  # "${FALCOSECURITY_LIBS_CMAKE_SOURCE_DIR}")

  execute_process(COMMAND "${CMAKE_COMMAND}" --build . WORKING_DIRECTORY "${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR}")
  set(FALCOSECURITY_LIBS_SOURCE_DIR "${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR}/falcosecurity-libs-prefix/src/falcosecurity-libs")
endif()

add_definitions(-D_GNU_SOURCE)
add_definitions(-DHAS_CAPTURE)
if(MUSL_OPTIMIZED_BUILD)
  add_definitions(-DMUSL_OPTIMIZED)
endif()

set(DRIVER_VERSION "${FALCOSECURITY_LIBS_VERSION}")
set(DRIVER_NAME "falco")
set(DRIVER_PACKAGE_NAME "falco")
set(SCAP_BPF_PROBE_ENV_VAR_NAME "FALCO_BPF_PROBE")
set(SCAP_HOST_ROOT_ENV_VAR_NAME "HOST_ROOT")

if(NOT LIBSCAP_DIR)
  set(LIBSCAP_DIR "${FALCOSECURITY_LIBS_SOURCE_DIR}")
endif()
set(LIBSINSP_DIR "${FALCOSECURITY_LIBS_SOURCE_DIR}")

# explicitly disable the tests/examples of this dependency
set(CREATE_TEST_TARGETS OFF CACHE BOOL "")
set(BUILD_LIBSCAP_EXAMPLES OFF CACHE BOOL "")

# todo(leogr): although Falco does not actually depend on chisels, we need this for the lua_parser. 
# Hopefully, we can switch off this in the future
set(WITH_CHISEL ON CACHE BOOL "")

set(USE_BUNDLED_TBB ON CACHE BOOL "")
set(USE_BUNDLED_B64 ON CACHE BOOL "")
set(USE_BUNDLED_JSONCPP ON CACHE BOOL "")
set(USE_BUNDLED_LUAJIT ON CACHE BOOL "")

list(APPEND CMAKE_MODULE_PATH "${FALCOSECURITY_LIBS_SOURCE_DIR}/cmake/modules")

include(CheckSymbolExists)
check_symbol_exists(strlcpy "string.h" HAVE_STRLCPY)
if(HAVE_STRLCPY)
	message(STATUS "Existing strlcpy found, will *not* use local definition by setting -DHAVE_STRLCPY.")
	add_definitions(-DHAVE_STRLCPY)
else()
	message(STATUS "No strlcpy found, will use local definition")
endif()

include(libscap)
include(libsinsp)

