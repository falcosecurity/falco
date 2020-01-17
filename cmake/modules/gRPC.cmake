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

if(NOT USE_BUNDLED_DEPS)
  # zlib
  include(FindZLIB)
  set(ZLIB_INCLUDE "${ZLIB_INCLUDE_DIRS}")
  set(ZLIB_LIB "${ZLIB_LIBRARIES}")

  if(ZLIB_INCLUDE AND ZLIB_LIB)
    message(STATUS "Found zlib: include: ${ZLIB_INCLUDE}, lib: ${ZLIB_LIB}")
  endif()

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
  if(PROTOC
     AND PROTOBUF_INCLUDE
     AND PROTOBUF_LIB)
    message(STATUS "Found protobuf: compiler: ${PROTOC}, include: ${PROTOBUF_INCLUDE}, lib: ${PROTOBUF_LIB}")
  else()
    message(FATAL_ERROR "Couldn't find system protobuf")
  endif()

  # gRPC todo(fntlnz, leodido): check that gRPC version is greater or equal than 1.8.0
  find_path(GRPCXX_INCLUDE NAMES grpc++/grpc++.h)
  if(GRPCXX_INCLUDE)
    set(GRPC_INCLUDE ${GRPCXX_INCLUDE})
  else()
    find_path(GRPCPP_INCLUDE NAMES grpcpp/grpcpp.h)
    set(GRPC_INCLUDE ${GRPCPP_INCLUDE})
    add_definitions(-DGRPC_INCLUDE_IS_GRPCPP=1)
  endif()
  find_library(GRPC_LIB NAMES grpc)
  find_library(GRPCPP_LIB NAMES grpc++)
  if(GRPC_INCLUDE
     AND GRPC_LIB
     AND GRPCPP_LIB)
    message(STATUS "Found grpc: include: ${GRPC_INCLUDE}, C lib: ${GRPC_LIB}, C++ lib: ${GRPCPP_LIB}")
  else()
    message(FATAL_ERROR "Couldn't find system grpc")
  endif()
  find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin)
  if(NOT GRPC_CPP_PLUGIN)
    message(FATAL_ERROR "System grpc_cpp_plugin not found")
  endif()

else()
  set(GRPC_SRC "${PROJECT_BINARY_DIR}/grpc-prefix/src/grpc")
  set(GRPC_INCLUDE "${GRPC_SRC}/include")
  set(GRPC_LIBS_ABSOLUTE "${GRPC_SRC}/libs/opt")
  set(GRPC_LIB "${GRPC_LIBS_ABSOLUTE}/libgrpc.a")
  set(GRPCPP_LIB "${GRPC_LIBS_ABSOLUTE}/libgrpc++.a")
  set(GRPC_CPP_PLUGIN "${GRPC_SRC}/bins/opt/grpc_cpp_plugin")

  # we tell gRPC to compile protobuf for us because when a gRPC package is not available, like on CentOS, it's very
  # likely that protobuf will be very outdated
  set(PROTOBUF_INCLUDE "${GRPC_SRC}/third_party/protobuf/src")
  set(PROTOC "${PROTOBUF_INCLUDE}/protoc")
  set(PROTOBUF_LIB "${GRPC_LIBS_ABSOLUTE}/protobuf/libprotobuf.a")
  # we tell gRPC to compile zlib for us because when a gRPC package is not available, like on CentOS, it's very likely
  # that zlib will be very outdated
  set(ZLIB_INCLUDE "${GRPC_SRC}/third_party/zlib")
  set(ZLIB_LIB "${GRPC_LIBS_ABSOLUTE}/libz.a")

  message(STATUS "Using bundled gRPC in '${GRPC_SRC}'")
  message(
    STATUS
      "Bundled gRPC comes with ---> protobuf: compiler: ${PROTOC}, include: ${PROTOBUF_INCLUDE}, lib: ${PROTOBUF_LIB}")
  message(STATUS "Bundled gRPC comes with ---> zlib: include: ${ZLIB_INCLUDE}, lib: ${ZLIB_LIB}}")
  message(STATUS "Bundled gRPC comes with ---> gRPC cpp plugin: include: ${GRPC_CPP_PLUGIN}")

  get_filename_component(PROTOC_DIR ${PROTOC} PATH)

  ExternalProject_Add(
    grpc
    GIT_REPOSITORY https://github.com/grpc/grpc.git
    GIT_TAG v1.26.0
    GIT_SUBMODULES "third_party/protobuf third_party/zlib third_party/cares/cares"
    BUILD_IN_SOURCE 1
    BUILD_BYPRODUCTS ${GRPC_LIB} ${GRPCPP_LIB}
    INSTALL_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND
      CFLAGS=-Wno-implicit-fallthrough
      HAS_SYSTEM_ZLIB=false
      HAS_SYSTEM_PROTOBUF=false
      HAS_SYSTEM_CARES=false
      PATH=${PROTOC_DIR}:$ENV{PATH}
      make
      static_cxx
      static_c
      grpc_cpp_plugin)
endif()
