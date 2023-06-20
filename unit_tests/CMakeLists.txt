#
# Copyright (C) 2023 The Falco Authors.
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

message(STATUS "Falco unit tests build enabled")

include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        release-1.12.1
)

FetchContent_MakeAvailable(googletest)

file(GLOB_RECURSE ENGINE_TESTS ${CMAKE_CURRENT_SOURCE_DIR}/engine/*.cpp)
file(GLOB_RECURSE FALCO_TESTS ${CMAKE_CURRENT_SOURCE_DIR}/falco/*.cpp)

set(FALCO_UNIT_TESTS_SOURCES
  "${ENGINE_TESTS}"
  falco/test_configuration.cpp
  falco/app/actions/test_select_event_sources.cpp
)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
  list(APPEND FALCO_UNIT_TESTS_SOURCES
    falco/test_atomic_signal_handler.cpp
    falco/app/actions/test_configure_interesting_sets.cpp
    falco/app/actions/test_configure_syscall_buffer.cpp)
endif()

set(FALCO_UNIT_TESTS_INCLUDES
    PRIVATE
    ${CMAKE_SOURCE_DIR}/userspace
    ${CMAKE_BINARY_DIR}/userspace/falco # we need it to include indirectly `config_falco.h` file
    ${CMAKE_SOURCE_DIR}/userspace/engine # we need it to include indirectly `falco_common.h` file
)

set(FALCO_UNIT_TESTS_DEPENDENCIES
  gtest
  gtest_main
  falco_application
)

get_target_property(FALCO_APPLICATION_LIBRARIES falco_application LINK_LIBRARIES)

set(FALCO_UNIT_TESTS_LIBRARIES
  gtest
  gtest_main
  falco_application
  ${FALCO_APPLICATION_LIBRARIES}
)

message(STATUS "FALCO_UNIT_TESTS_SOURCES: ${FALCO_UNIT_TESTS_SOURCES}")
message(STATUS "FALCO_UNIT_TESTS_INCLUDES: ${FALCO_UNIT_TESTS_INCLUDES}")
message(STATUS "FALCO_UNIT_TESTS_DEPENDENCIES: ${FALCO_UNIT_TESTS_DEPENDENCIES}")
message(STATUS "FALCO_UNIT_TESTS_LIBRARIES: ${FALCO_UNIT_TESTS_LIBRARIES}")

add_executable(falco_unit_tests ${FALCO_UNIT_TESTS_SOURCES})
target_include_directories(falco_unit_tests ${FALCO_UNIT_TESTS_INCLUDES})
target_link_libraries(falco_unit_tests ${FALCO_UNIT_TESTS_LIBRARIES})
add_dependencies(falco_unit_tests ${FALCO_UNIT_TESTS_DEPENDENCIES})

if (EMSCRIPTEN)
	target_compile_options(falco_unit_tests PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
	target_link_options(falco_unit_tests PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
	target_link_options(falco_unit_tests PRIVATE "-sEXPORTED_FUNCTIONS=['_main','_htons','_ntohs']")
endif()
