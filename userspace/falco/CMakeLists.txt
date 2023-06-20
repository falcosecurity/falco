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

configure_file(config_falco.h.in config_falco.h)

set(
  FALCO_SOURCES
  app/app.cpp
  app/options.cpp
  app/restart_handler.cpp
  app/actions/helpers_generic.cpp
  app/actions/helpers_inspector.cpp
  app/actions/configure_interesting_sets.cpp
  app/actions/create_signal_handlers.cpp
  app/actions/daemonize.cpp
  app/actions/init_falco_engine.cpp
  app/actions/init_inspectors.cpp
  app/actions/init_clients.cpp
  app/actions/init_outputs.cpp
  app/actions/list_fields.cpp
  app/actions/list_plugins.cpp
  app/actions/load_config.cpp
  app/actions/load_plugins.cpp
  app/actions/load_rules_files.cpp
  app/actions/process_events.cpp
  app/actions/print_generated_gvisor_config.cpp
  app/actions/print_help.cpp
  app/actions/print_ignored_events.cpp
  app/actions/print_plugin_info.cpp
  app/actions/print_support.cpp
  app/actions/print_syscall_events.cpp
  app/actions/print_version.cpp
  app/actions/print_page_size.cpp
  app/actions/configure_syscall_buffer_size.cpp
  app/actions/configure_syscall_buffer_num.cpp
  app/actions/select_event_sources.cpp
  app/actions/start_grpc_server.cpp
  app/actions/start_webserver.cpp
  app/actions/validate_rules_files.cpp
  app/actions/create_requested_paths.cpp
  configuration.cpp
  logger.cpp
  falco_outputs.cpp
  outputs_file.cpp
  outputs_program.cpp
  outputs_stdout.cpp
  outputs_syslog.cpp
  event_drops.cpp
  stats_writer.cpp
  versions_info.cpp
)

set(
  FALCO_INCLUDE_DIRECTORIES
  "${PROJECT_SOURCE_DIR}/userspace/engine"
  "${PROJECT_BINARY_DIR}/userspace/falco"
  "${PROJECT_BINARY_DIR}/driver/src"
  "${CXXOPTS_INCLUDE_DIR}"
  "${YAMLCPP_INCLUDE_DIR}"
  "${CMAKE_CURRENT_BINARY_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}"
)

list(APPEND FALCO_INCLUDE_DIRECTORIES "${FALCO_EXTRA_INCLUDE_DIRS}")

set(
  FALCO_DEPENDENCIES
  b64
  cxxopts
)

set(
  FALCO_LIBRARIES
  falco_engine
  sinsp
  "${YAMLCPP_LIB}"
)

if(USE_BUNDLED_DEPS)
  list(APPEND FALCO_DEPENDENCIES yamlcpp)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux" AND NOT MINIMAL_BUILD)
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
    "${CPPHTTPLIB_INCLUDE}"
    "${OPENSSL_INCLUDE_DIR}"
    "${GRPC_INCLUDE}"
    "${GRPCPP_INCLUDE}"
    "${PROTOBUF_INCLUDE}"
    "${CARES_INCLUDE}"
  )

  if(CMAKE_SYSTEM_NAME MATCHES "Linux" AND USE_BUNDLED_GRPC)
    list(APPEND FALCO_DEPENDENCIES grpc)
    list(APPEND FALCO_LIBRARIES "${GRPC_LIBRARIES}")
  endif()

  list(APPEND FALCO_DEPENDENCIES cpp-httplib)

  list(
    APPEND FALCO_LIBRARIES
    "${GRPCPP_LIB}"
    "${GRPC_LIB}"
    "${GPR_LIB}"
    "${PROTOBUF_LIB}"
    "${CARES_LIB}"
    "${OPENSSL_LIBRARIES}"
    "${YAMLCPP_LIB}"
  )
endif()

add_library(
  falco_application STATIC
  ${FALCO_SOURCES}
)

add_dependencies(falco_application ${FALCO_DEPENDENCIES})

target_link_libraries(
  falco_application
  ${FALCO_LIBRARIES}
)

target_include_directories(
  falco_application
  PUBLIC
  ${FALCO_INCLUDE_DIRECTORIES}
)

add_executable(falco falco.cpp)
add_dependencies(falco falco_application ${FALCO_DEPENDENCIES})
target_link_libraries(falco falco_application ${FALCO_LIBRARIES})
target_include_directories(falco PUBLIC ${FALCO_INCLUDE_DIRECTORIES})

if(CMAKE_SYSTEM_NAME MATCHES "Linux" AND NOT MINIMAL_BUILD)
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

install(TARGETS falco RUNTIME DESTINATION ${FALCO_BIN_DIR} COMPONENT "${FALCO_COMPONENT_NAME}")
