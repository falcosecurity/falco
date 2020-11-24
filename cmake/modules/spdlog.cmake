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


set(SPDLOG_PREFIX "${PROJECT_BINARY_DIR}/spdlog-prefix")
set(SPDLOG_INCLUDE_DIR "${SPDLOG_PREFIX}/src/spdlog/include")
message(STATUS "Using bundled spdlog in '${SPDLOG_INCLUDE_DIR}'")

ExternalProject_Add(
  spdlog
  URL "https://github.com/gabime/spdlog/archive/v1.8.1.tar.gz"
  URL_HASH "SHA256=5197b3147cfcfaa67dd564db7b878e4a4b3d9f3443801722b3915cdeced656cb"
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
)