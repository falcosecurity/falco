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

option(
  BUILD_STATIC_PROTOBUF
  "Build a static version of protobuf (useful for building in Operating Systems that don't have the protobuf package)"
  OFF)

if(NOT BUILD_STATIC_PROTOBUF)
  # todo(fntlnz, leodido): check that protobuf version is greater or equal than 3.5.0
  find_program(PROTOC NAMES protoc)
  find_path(PROTOBUF_INCLUDE NAMES google/protobuf/message.h)
  find_library(PROTOBUF_LIB NAMES libprotobuf.so)
  if(PROTOC
     AND PROTOBUF_INCLUDE
     AND PROTOBUF_LIB)
    message(STATUS "Found protobuf: compiler: ${PROTOC}, include: ${PROTOBUF_INCLUDE}, lib: ${PROTOBUF_LIB}")
  else()
    message(FATAL_ERROR "Couldn't find system protobuf")
  endif()
else()
  set(PROTOBUF_SRC "${PROJECT_BINARY_DIR}/protobuf-prefix/src/protobuf")
  message(STATUS "Using bundled protobuf in '${PROTOBUF_SRC}'")
  set(PROTOC "${PROTOBUF_SRC}/target/bin/protoc")
  set(PROTOBUF_INCLUDE "${PROTOBUF_SRC}/target/include")
  set(PROTOBUF_LIB "${PROTOBUF_SRC}/target/lib/libprotobuf.a")
  ExternalProject_Add(
    protobuf
    URL "https://github.com/protocolbuffers/protobuf/releases/download/v3.8.0/protobuf-cpp-3.8.0.tar.gz"
    URL_MD5 "9054bb5571905a28b3ae787d1d6cf8de"
    CONFIGURE_COMMAND /usr/bin/env ./configure --with-zlib --prefix=${PROTOBUF_SRC}/target
    BUILD_COMMAND ${CMD_MAKE}
    BUILD_IN_SOURCE 1
    BUILD_BYPRODUCTS ${PROTOC} ${PROTOBUF_INCLUDE} ${PROTOBUF_LIB}
    INSTALL_COMMAND make install)
endif()
