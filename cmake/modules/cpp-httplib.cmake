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

option(USE_BUNDLED_CPPHTTPLIB "Enable building of the bundled cpp-httplib" ${USE_BUNDLED_DEPS})

if(USE_BUNDLED_CPPHTTPLIB)
    include(FetchContent)
    FetchContent_Declare(cpp-httplib
        URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.15.3.tar.gz
        URL_HASH SHA256=2121bbf38871bb2aafb5f7f2b9b94705366170909f434428352187cb0216124e
    )
    FetchContent_MakeAvailable(cpp-httplib)
else()
    find_package(httplib CONFIG REQUIRED)
endif()
