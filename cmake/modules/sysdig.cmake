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

set(SYSDIG_WORKING_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/sysdig-repo")
set(SYSDIG_REPO_DIR "${CMAKE_BINARY_DIR}/sysdig-repo")

file(MAKE_DIRECTORY ${SYSDIG_REPO_DIR})
# cd /path/to/build && cmake /path/to/source
execute_process(COMMAND "${CMAKE_COMMAND}" ${SYSDIG_WORKING_DIR} WORKING_DIRECTORY ${SYSDIG_REPO_DIR})

# todo(leodido, fntlnz) > use the following one when CMake version will be >= 3.13

# execute_process(COMMAND "${CMAKE_COMMAND}" -B ${SYSDIG_REPO_DIR} WORKING_DIRECTORY "${SYSDIG_WORKING_DIR}")

execute_process(COMMAND "${CMAKE_COMMAND}" --build . WORKING_DIRECTORY "${SYSDIG_REPO_DIR}")
set(SYSDIG_SOURCE_DIR "${SYSDIG_REPO_DIR}/sysdig-prefix/src/sysdig")

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
add_dependencies(sinsp tbb b64 luajit)

if(USE_BUNDLED_DEPS)
  add_dependencies(scap grpc curl jq)
endif()
