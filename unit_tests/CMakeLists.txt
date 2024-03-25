# SPDX-License-Identifier: Apache-2.0
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
  GIT_TAG        v1.14.0
)

FetchContent_MakeAvailable(googletest)

# Create a libscap_test_var.h file with some variables used by our tests
# for example the kmod path or the bpf path.
configure_file (
    ${CMAKE_CURRENT_SOURCE_DIR}/falco_test_var.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/falco_test_var.h
)

add_executable(falco_unit_tests
    test_falco_engine.cpp
    engine/test_add_source.cpp
    engine/test_alt_rule_loader.cpp
    engine/test_enable_rule.cpp
    engine/test_falco_utils.cpp
    engine/test_filter_details_resolver.cpp
    engine/test_filter_macro_resolver.cpp
    engine/test_filter_warning_resolver.cpp
    engine/test_plugin_requirements.cpp
    engine/test_rule_loader.cpp
    engine/test_rulesets.cpp
    falco/test_configuration.cpp
    falco/app/actions/test_select_event_sources.cpp
    falco/app/actions/test_load_config.cpp
)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_sources(falco_unit_tests
    PRIVATE
        falco/test_atomic_signal_handler.cpp
        falco/app/actions/test_configure_interesting_sets.cpp
        falco/app/actions/test_configure_syscall_buffer_num.cpp
    )
endif()

target_include_directories(falco_unit_tests
PRIVATE
    ${CMAKE_SOURCE_DIR}/userspace
    ${CMAKE_BINARY_DIR}/userspace/falco # we need it to include indirectly `config_falco.h` file
    ${CMAKE_SOURCE_DIR}/userspace/engine # we need it to include indirectly `falco_common.h` file
    ${CMAKE_CURRENT_BINARY_DIR} # we need it to include `falco_test_var.h`
)

get_target_property(FALCO_APPLICATION_LIBRARIES falco_application LINK_LIBRARIES)

target_link_libraries(falco_unit_tests
    falco_application
    GTest::gtest
    GTest::gtest_main
    ${FALCO_APPLICATION_LIBRARIES}
)

if (EMSCRIPTEN)
	target_compile_options(falco_unit_tests PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
	target_link_options(falco_unit_tests PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
  target_link_options(falco_unit_tests PRIVATE "-sALLOW_MEMORY_GROWTH=1")
	target_link_options(falco_unit_tests PRIVATE "-sEXPORTED_FUNCTIONS=['_main','_htons','_ntohs']")
endif()
