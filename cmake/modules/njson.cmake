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

if(USE_BUNDLED_NLOHMANN_JSON)
    ExternalProject_Add(njson
        URL "https://github.com/nlohmann/json/archive/v3.3.0.tar.gz"
        URL_HASH "SHA256=2fd1d207b4669a7843296c41d3b6ac5b23d00dec48dba507ba051d14564aa801"
        CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DJSON_BuildTests=OFF -DBUILD_TESTING=OFF
    )
endif()
