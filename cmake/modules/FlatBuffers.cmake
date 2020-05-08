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

if(NOT USE_BUNDLED_DEPS)
  find_program(FLATBUFFERS_FLATC_EXECUTABLE NAMES flatc)
  find_path(FLATBUFFERS_INCLUDE_DIR NAMES flatbuffers/flatbuffers.h)

  if(FLATBUFFERS_FLATC_EXECUTABLE AND FLATBUFFERS_INCLUDE_DIR)
    message(STATUS "Found flatbuffers: include: ${FLATBUFFERS_INCLUDE_DIR}, flatc: ${FLATBUFFERS_FLATC_EXECUTABLE}")
  else()
    message(FATAL_ERROR "Couldn't find system flatbuffers")
  endif()
else()
  include(ExternalProject)

  set(FLATBUFFERS_PREFIX ${CMAKE_BINARY_DIR}/flatbuffers-prefix)
  set(FLATBUFFERS_FLATC_EXECUTABLE
      ${FLATBUFFERS_PREFIX}/bin/flatc
      CACHE INTERNAL "FlatBuffer compiler")
  set(FLATBUFFERS_INCLUDE_DIR
      ${FLATBUFFERS_PREFIX}/include
      CACHE INTERNAL "FlatBuffer include directory")

  ExternalProject_Add(
    flatbuffers
    PREFIX ${FLATBUFFERS_PREFIX}
    GIT_REPOSITORY "https://github.com/google/flatbuffers.git"
    GIT_TAG "v1.12.0"
    CMAKE_ARGS
      -DCMAKE_INSTALL_PREFIX=${FLATBUFFERS_PREFIX}
      -DCMAKE_BUILD_TYPE=Release
      -DFLATBUFFERS_CODE_COVERAGE=OFF
      -DFLATBUFFERS_BUILD_TESTS=OFF
      -DFLATBUFFERS_INSTALL=ON
      -DFLATBUFFERS_BUILD_FLATLIB=OFF
      -DFLATBUFFERS_BUILD_FLATC=ON
      -DFLATBUFFERS_BUILD_FLATHASH=OFF
      -DFLATBUFFERS_BUILD_GRPCTEST=OFF
      -DFLATBUFFERS_BUILD_SHAREDLIB=OFF
    BUILD_BYPRODUCTS ${FLATBUFFERS_FLATC_EXECUTABLE})
endif()

# From FindFlatBuffer.cmake
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(FlatBuffers DEFAULT_MSG FLATBUFFERS_FLATC_EXECUTABLE FLATBUFFERS_INCLUDE_DIR)

if(FLATBUFFERS_FOUND)
  function(FLATBUFFERS_GENERATE_C_HEADERS Name)
    set(FLATC_OUTPUTS)
    foreach(FILE ${ARGN})
      get_filename_component(FLATC_OUTPUT ${FILE} NAME_WE)
      set(FLATC_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${FLATC_OUTPUT}_generated.h")

      list(APPEND FLATC_OUTPUTS ${FLATC_OUTPUT})

      add_custom_command(
        OUTPUT ${FLATC_OUTPUT}
        COMMAND ${FLATBUFFERS_FLATC_EXECUTABLE} ARGS -c -o "${CMAKE_CURRENT_BINARY_DIR}/" ${FILE}
        DEPENDS ${FILE}
        COMMENT "Building C++ header for ${FILE}"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    endforeach()
    set(${Name}_OUTPUTS
        ${FLATC_OUTPUTS}
        PARENT_SCOPE)
  endfunction()

  set(FLATBUFFERS_INCLUDE_DIRS ${FLATBUFFERS_INCLUDE_DIR})
  include_directories(${CMAKE_BINARY_DIR})
else()
  set(FLATBUFFERS_INCLUDE_DIR)
endif()
