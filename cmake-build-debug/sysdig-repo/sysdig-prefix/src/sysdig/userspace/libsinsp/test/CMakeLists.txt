#
# Copyright (C) 2019 Sysdig Inc.
#
# This file is part of sysdig .
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

include_directories("${GTEST_INCLUDE_DIR}")
include_directories("${JSONCPP_INCLUDE}")
include_directories("${TBB_INCLUDE_DIR}")
include_directories("${CURL_INCLUDE_DIR}")

include_directories("..")
include_directories("../../libscap")

add_executable(unit-test-libsinsp
	cgroup_list_counter.ut.cpp
	sinsp.ut.cpp
)

target_link_libraries(unit-test-libsinsp
	"${GTEST_LIB}"
	"${GTEST_MAIN_LIB}"
	sinsp
)

add_custom_target(run-unit-test-libsinsp
	DEPENDS unit-test-libsinsp
	COMMAND unit-test-libsinsp
)
