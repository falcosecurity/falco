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

# The sysdig git reference (branch name, commit hash, or tag)
# set(SYSDIG_VERSION "falco/${FALCO_VERSION_MAJOR}.${FALCO_VERSION_MINOR}.${FALCO_VERSION_PATCH}") # todo(leodido, fntlnz) > use this when FALCO_VERSION variable is ok (PR 872)
set(SYSDIG_VERSION "falco/0.18.0")

ExternalProject_Add(
  sysdig
  GIT_REPOSITORY https://github.com/draios/sysdig.git
  GIT_TAG ${SYSDIG_VERSION}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
  TEST_COMMAND "")

# Fetch the sysdig source directory
ExternalProject_Get_property(sysdig SOURCE_DIR)
set(SYSDIG_SOURCE_DIR "${SOURCE_DIR}")
unset(SOURCE_DIR)
message(STATUS "Source directory of sysdig: ${SYSDIG_SOURCE_DIR}")

#
# ExternalProject_Get_property(sysdig BINARY_DIR)
# set(SYSDIG_BINARY_DIR "${BINARY_DIR}")
# unset(BINARY_DIR)
# message(STATUS "Source directory of sysdig: ${SYSDIG_BINARY_DIR}")

list(APPEND CMAKE_MODULE_PATH "${SYSDIG_SOURCE_DIR}/cmake/modules")
include(FindMakedev)

# jsoncpp
set(JSONCPP_SRC "${SYSDIG_SOURCE_DIR}/userspace/libsinsp/third-party/jsoncpp")
set(JSONCPP_INCLUDE "${JSONCPP_SRC}")
set(JSONCPP_LIB_SRC "${JSONCPP_SRC}/jsoncpp.cpp")

# Add driver directory
add_subdirectory("${SYSDIG_SOURCE_DIR}/driver" "${PROJECT_BINARY_DIR}/driver")

# Add libscap directory
add_subdirectory("${SYSDIG_SOURCE_DIR}/userspace/libscap" "${PROJECT_BINARY_DIR}/userspace/libscap")

# Add libsinsp directory
add_subdirectory("${SYSDIG_SOURCE_DIR}/userspace/libsinsp" "${PROJECT_BINARY_DIR}/userspace/libsinsp")
