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

set(CXXOPTS_SRC "${PROJECT_BINARY_DIR}/cxxopts-prefix/src/cxxopts/")
set(CXXOPTS_INCLUDE_DIR "${CXXOPTS_SRC}/include")

ExternalProject_Add(
        cxxopts
        URL "https://github.com/jarro2783/cxxopts/archive/refs/tags/v3.0.0.tar.gz"
        URL_HASH "SHA256=36f41fa2a46b3c1466613b63f3fa73dc24d912bc90d667147f1e43215a8c6d00"
	CONFIGURE_COMMAND ""
	BUILD_COMMAND ""
	INSTALL_COMMAND "")
