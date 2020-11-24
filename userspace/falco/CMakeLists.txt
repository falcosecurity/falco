#
# Copyright (C) 2020 The Falco Authors.
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

configure_file(config_falco.h.in config_falco.h)

set(
  FALCO_SOURCES
  configuration.cpp
  logger.cpp
  falco_outputs.cpp
  outputs_file.cpp
  outputs_program.cpp
  outputs_stdout.cpp
  outputs_syslog.cpp
  event_drops.cpp
  statsfilewriter.cpp
  falco.cpp
  "${SYSDIG_SOURCE_DIR}/userspace/libsinsp/fields_info.cpp"
)

set(
  FALCO_INCLUDE_DIRECTORIES
  "${PROJECT_SOURCE_DIR}/userspace/engine"
  "${PROJECT_BINARY_DIR}/userspace/falco"
  "${PROJECT_BINARY_DIR}/driver/src"
  "${SPDLOG_INCLUDE_DIR}"
  "${STRING_VIEW_LITE_INCLUDE}"
  "${YAMLCPP_INCLUDE_DIR}"
  "${CMAKE_CURRENT_BINARY_DIR}"
  "${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include"
)

set(
  FALCO_DEPENDENCIES
  spdlog
  string-view-lite
  libyaml
  b64
  luajit
  lpeg
  lyaml
)

set(
  FALCO_LIBRARIES
  falco_engine
  sinsp
  "${LIBYAML_LIB}"
  "${YAMLCPP_LIB}"
)

if(USE_BUNDLED_DEPS)
  list(APPEND FALCO_DEPENDENCIES yamlcpp)
endif()

if(NOT MINIMAL_BUILD)
  list(
    APPEND FALCO_SOURCES
    outputs_grpc.cpp
    outputs_http.cpp
    webserver.cpp
    grpc_context.cpp
    grpc_server_impl.cpp
    grpc_request_context.cpp
    grpc_server.cpp
    grpc_context.cpp
    grpc_server_impl.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/version.grpc.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/version.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/outputs.grpc.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/outputs.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/schema.pb.cc
  )

  list(
    APPEND FALCO_INCLUDE_DIRECTORIES
    "${CIVETWEB_INCLUDE_DIR}"
    "${OPENSSL_INCLUDE_DIR}"
    "${GRPC_INCLUDE}"
    "${GRPCPP_INCLUDE}"
    "${PROTOBUF_INCLUDE}"
  )

  list(APPEND FALCO_DEPENDENCIES civetweb)

  list(
    APPEND FALCO_LIBRARIES
    "${GPR_LIB}"
    "${GRPC_LIB}"
    "${GRPCPP_LIB}"
    "${PROTOBUF_LIB}"
    "${OPENSSL_LIBRARY_SSL}"
    "${OPENSSL_LIBRARY_CRYPTO}"
    "${LIBYAML_LIB}"
    "${YAMLCPP_LIB}"
    "${CIVETWEB_LIB}"
  )
endif()

add_executable(
  falco
  ${FALCO_SOURCES}
)

add_dependencies(falco ${FALCO_DEPENDENCIES})

target_link_libraries(
  falco
  ${FALCO_LIBRARIES}
)

target_include_directories(
  falco
  PUBLIC
  ${FALCO_INCLUDE_DIRECTORIES}
)

if(NOT MINIMAL_BUILD)
  add_custom_command(
    TARGET falco
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/verify_engine_fields.sh ${CMAKE_SOURCE_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Comparing engine fields checksum in falco_engine.h to actual fields"
  )
else()
  message(STATUS "Skipping engine fields checksum when building the minimal Falco.")
endif()

if(NOT MINIMAL_BUILD)
  add_custom_command(
    OUTPUT
    ${CMAKE_CURRENT_BINARY_DIR}/version.grpc.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/version.grpc.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/version.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/version.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/outputs.grpc.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/outputs.grpc.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/outputs.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/outputs.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/schema.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/schema.pb.h
    COMMENT "Generate gRPC API"
    # Falco gRPC Version API
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/version.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR} --cpp_out=. ${CMAKE_CURRENT_SOURCE_DIR}/version.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR} --grpc_out=. --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN}
    ${CMAKE_CURRENT_SOURCE_DIR}/version.proto
    # Falco gRPC Outputs API
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/outputs.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR} --cpp_out=. ${CMAKE_CURRENT_SOURCE_DIR}/outputs.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/schema.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR} --grpc_out=. --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN}
    ${CMAKE_CURRENT_SOURCE_DIR}/outputs.proto
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
endif()

# strip the Falco binary when releasing using musl
if(MUSL_OPTIMIZED_BUILD AND CMAKE_BUILD_TYPE STREQUAL "release")
  add_custom_command(
    TARGET falco
    POST_BUILD
    COMMAND ${CMAKE_STRIP} --strip-unneeded falco
    COMMENT "Strip the Falco binary when releasing the musl build"
  )
endif()

install(TARGETS falco DESTINATION ${FALCO_BIN_DIR})
