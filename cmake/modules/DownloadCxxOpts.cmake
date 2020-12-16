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

set(CXXOPTS_PREFIX ${CMAKE_BINARY_DIR}/cxxopts-prefix)
set(CXXOPTS_INCLUDE ${CXXOPTS_PREFIX}/include)
message(STATUS "Using bundled cxxopts in ${CXXOPTS_INCLUDE}")

ExternalProject_Add(
  cxxopts
  PREFIX ${CXXOPTS_PREFIX}
  GIT_REPOSITORY "https://github.com/jarro2783/cxxopts.git"
  GIT_TAG "master"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy ${CXXOPTS_PREFIX}/src/cxxopts/include/cxxopts.hpp
                  ${CXXOPTS_INCLUDE}/cxxopts.hpp)
