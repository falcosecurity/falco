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

set(DRIVER_CMAKE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/driver-repo")
set(DRIVER_CMAKE_WORKING_DIR "${CMAKE_BINARY_DIR}/driver-repo")

file(MAKE_DIRECTORY ${DRIVER_CMAKE_WORKING_DIR})

if(DRIVER_SOURCE_DIR)
  set(DRIVER_VERSION "0.0.0-local")
  message(STATUS "Using local version for driver: '${DRIVER_SOURCE_DIR}'")
else()
  # DRIVER_VERSION accepts a git reference (branch name, commit hash, or tag) to the falcosecurity/libs repository
  # which contains the driver source code under the `/driver` directory.
  # The chosen driver version must be compatible with the given FALCOSECURITY_LIBS_VERSION.
  # In case you want to test against another driver version (or branch, or commit) just pass the variable -
  # ie., `cmake -DDRIVER_VERSION=dev ..`
  if(NOT DRIVER_VERSION)
    set(DRIVER_VERSION "090f4f08c341ef1bb866170deef1c6b72e7e5d43")
    set(DRIVER_CHECKSUM "SHA256=8b24b8ebb83c5d0a323e5ab0d8b8858ec2ffa5b6d0496c9eab9b5c796f7ced3b")
  endif()

  # cd /path/to/build && cmake /path/to/source
  execute_process(COMMAND "${CMAKE_COMMAND}" -DDRIVER_VERSION=${DRIVER_VERSION} -DDRIVER_CHECKSUM=${DRIVER_CHECKSUM}
    ${DRIVER_CMAKE_SOURCE_DIR} WORKING_DIRECTORY ${DRIVER_CMAKE_WORKING_DIR})

  # cmake --build .
  execute_process(COMMAND "${CMAKE_COMMAND}" --build . WORKING_DIRECTORY "${DRIVER_CMAKE_WORKING_DIR}")
  set(DRIVER_SOURCE_DIR "${DRIVER_CMAKE_WORKING_DIR}/driver-prefix/src/driver")
endif()

add_definitions(-D_GNU_SOURCE)

set(DRIVER_NAME "falco")
set(DRIVER_PACKAGE_NAME "falco")
set(DRIVER_COMPONENT_NAME "falco-driver")

add_subdirectory(${DRIVER_SOURCE_DIR} ${PROJECT_BINARY_DIR}/driver)
