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

include(ExternalProject)

set(STRING_VIEW_LITE_PREFIX ${CMAKE_BINARY_DIR}/string-view-lite-prefix)
set(STRING_VIEW_LITE_INCLUDE ${STRING_VIEW_LITE_PREFIX}/include)
message(STATUS "Found string-view-lite: include: ${STRING_VIEW_LITE_INCLUDE}")

ExternalProject_Add(
  string-view-lite
  PREFIX ${STRING_VIEW_LITE_PREFIX}
  GIT_REPOSITORY "https://github.com/martinmoene/string-view-lite.git"
  GIT_TAG "v1.4.0"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND
    ${CMAKE_COMMAND} -E copy ${STRING_VIEW_LITE_PREFIX}/src/string-view-lite/include/nonstd/string_view.hpp
    ${STRING_VIEW_LITE_INCLUDE}/nonstd/string_view.hpp)
