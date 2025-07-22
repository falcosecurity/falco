# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under
# the License.
#

option(USE_BUNDLED_CPPHTTPLIB "Enable building of the bundled cpp-httplib" ${USE_BUNDLED_DEPS})

if(USE_BUNDLED_CPPHTTPLIB)
	set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF)
	set(HTTPLIB_REQUIRE_BROTLI OFF)
	set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF)
	set(HTTPLIB_REQUIRE_ZLIB OFF)
	set(HTTPLIB_USE_ZSTD_IF_AVAILABLE OFF)
	set(HTTPLIB_REQUIRE_ZSTD OFF)
	set(HTTPLIB_USE_NON_BLOCKING_GETADDRINFO OFF)
	include(FetchContent)
	FetchContent_Declare(
		cpp-httplib
		URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.23.1.tar.gz
		URL_HASH SHA256=410a1347ed6bcbcc4a19af8ed8ad3873fe9fa97731d52db845c4c78f3f9c31e6
	)
	FetchContent_MakeAvailable(cpp-httplib)
else()
	find_package(httplib CONFIG REQUIRED)
endif()
