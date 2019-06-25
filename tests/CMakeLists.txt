#
# Copyright (C) 2016-2019 Draios Inc dba Sysdig.
#
# This file is part of falco .
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
set(FALCO_TESTS_SOURCES
    test_base.cpp)

set(FALCO_TESTED_LIBRARIES
    falco_engine)

option(FALCO_BUILD_TESTS "Determines whether to build tests." ON)

if(FALCO_BUILD_TESTS)
    enable_testing()
    if(NOT TARGET catch)
        include(FindCatch)
    endif()

	add_executable(falco_test ${FALCO_TESTS_SOURCES})

	target_link_libraries(falco_test PUBLIC ${FALCO_TESTED_LIBRARIES} catch)

	include(CTest)
	include(Catch)
	catch_discover_tests(falco_test)

	add_custom_target(tests COMMAND ${CMAKE_CTEST_COMMAND} DEPENDS falco_test)
endif()
