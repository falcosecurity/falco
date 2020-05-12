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

add_library(falco_profiler INTERFACE)

target_include_directories(falco_profiler INTERFACE "${HEDLEY_INCLUDE}" "${FLATBUFFER_INCLUDE_DIR}"
                                                    "${CMAKE_CURRENT_BINARY_DIR}")

flatbuffers_generate_c_headers(PROFILE "profile.fbs")
add_custom_target(flatbuffer_profiler DEPENDS ${PROFILE_OUTPUTS})
