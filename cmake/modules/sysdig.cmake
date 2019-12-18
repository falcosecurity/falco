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
# execute_process(COMMAND cmake -E make_directory ${SYSDIG_REPO_DIR})
execute_process(COMMAND "${CMAKE_COMMAND}" -B ${SYSDIG_REPO_DIR} WORKING_DIRECTORY "${SYSDIG_WORKING_DIR}")
execute_process(COMMAND "${CMAKE_COMMAND}" --build . WORKING_DIRECTORY "${SYSDIG_REPO_DIR}")
set(SYSDIG_SOURCE_DIR "${SYSDIG_REPO_DIR}/sysdig-prefix/src/sysdig")

# if(NOT SYSDIG_VERSION)
#   set(SYSDIG_VERSION "dev")
# endif()

# ExternalProject_Add(
#   sysdig
#   GIT_REPOSITORY https://github.com/draios/sysdig.git
#   GIT_TAG ${SYSDIG_VERSION}
#   CONFIGURE_COMMAND ""
#   BUILD_COMMAND ""
#   INSTALL_COMMAND ""
#   TEST_COMMAND "")

# # Fetch the sysdig source directory
# ExternalProject_Get_Property(sysdig SOURCE_DIR)
# set(SYSDIG_SOURCE_DIR "${SOURCE_DIR}")
# unset(SOURCE_DIR)
# message(STATUS "Source directory of sysdig: ${SYSDIG_SOURCE_DIR}")
# message(STATUS "Sysdig version: ${SYSDIG_VERSION}")

# set(LIBSCAP_CXX_FLAGS "${CMAKE_CXX_FLAGS}") set(LIBSCAP_C_FLAGS "${CMAKE_C_FLAGS}")

# ExternalProject_Add( libscap DOWNLOAD_COMMAND "" INSTALL_COMMAND "" SOURCE_DIR
# "${SYSDIG_SOURCE_DIR}/userspace/libscap" CMAKE_ARGS -DCMAKE_CXX_FLAGS=${LIBSCAP_CXX_FLAGS}
# -DCMAKE_C_FLAGS=${LIBSCAP_C_FLAGS} -DZLIB_INCLUDE=${ZLIB_INCLUDE} -DZLIB_LIB=${ZLIB_LIB} -DBUILD_LIBSCAP_EXAMPLES=OFF
# -DCMAKE_MODULE_PATH=${CMAKE_MODULE_PATH} ) target_compile_options(libscap -DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")

# set(LIBSINPS_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAS_CAPTURE") set(LIBSINPS_C_FLAGS "${CMAKE_C_FLAGS}")

# ExternalProject_Add( libsinsp DEPENDS sysdig DOWNLOAD_COMMAND "" INSTALL_COMMAND "" SOURCE_DIR
# "${SYSDIG_SOURCE_DIR}/userspace/libsinsp" CMAKE_ARGS -DCMAKE_CXX_FLAGS=${LIBSINPS_CXX_FLAGS}
# -DCMAKE_C_FLAGS=${LIBSINPS_C_FLAGS} -DPROTOBUF_INCLUDE=${PROTOBUF_INCLUDE} -DB64_INCLUDE=${B64_INCLUDE}
# -DJSONCPP_INCLUDE=${JSONCPP_INCLUDE} -DLUAJIT_INCLUDE=${LUAJIT_INCLUDE} -DTBB_INCLUDE_DIR=${TBB_INCLUDE_DIR}
# -DCURSES_INCLUDE_DIR=${CURSES_INCLUDE_DIR} -DGRPC_INCLUDE=${GRPC_INCLUDE} -DJQ_INCLUDE=${JQ_INCLUDE}
# -DOPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR} -DCURL_INCLUDE_DIR=${CURL_INCLUDE_DIR} -DCURL_LIBRARIES=${CURL_LIBRARIES}
# -DJSONCPP_LIB=${JSONCPP_LIB} -DTBB_LIB=${TBB_LIB} -DUSE_BUNDLED_LUAJIT=OFF -DUSE_BUNDLED_OPENSSL=OFF
# -DUSE_BUNDLED_CURL=OFF -DUSE_BUNDLED_TBB=OFF -DUSE_BUNDLED_GRPC=OFF -DGRPC_CPP_PLUGIN=${GRPC_CPP_PLUGIN}
# -DPROTOC=${PROTOC} -DOPENSSL_LIBRARIES=${OPENSSL_LIBRARIES} -DLUAJIT_LIB=${LUAJIT_LIB} )

# list(APPEND CMAKE_MODULE_PATH "${SYSDIG_SOURCE_DIR}/cmake/modules")
#

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
