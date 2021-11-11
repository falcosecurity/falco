#
# Copyright (C) 2021 The Falco Authors.
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
# Used internally by our patched civetweb cmakelists
set(OPENSSL_LIBRARIES "${OPENSSL_LIBRARY_SSL} ${OPENSSL_LIBRARY_CRYPTO}")

set(CIVETWEB_SRC "${PROJECT_BINARY_DIR}/civetweb-prefix/src/civetweb/")
set(CIVETWEB_LIB "${CIVETWEB_SRC}/install/lib/libcivetweb.a")
SET(CIVETWEB_CPP_LIB "${CIVETWEB_SRC}/install/lib/libcivetweb-cpp.a")
set(CIVETWEB_INCLUDE_DIR "${CIVETWEB_SRC}/install/include")
message(STATUS "Using bundled civetweb in '${CIVETWEB_SRC}'")
ExternalProject_Add(
        civetweb
        URL "https://github.com/civetweb/civetweb/archive/v1.15.tar.gz"
        URL_HASH "SHA256=90a533422944ab327a4fbb9969f0845d0dba05354f9cacce3a5005fa59f593b9"
        INSTALL_DIR ${CIVETWEB_SRC}/install
        CMAKE_ARGS
        -DBUILD_TESTING=off
        -DCIVETWEB_BUILD_TESTING=off
        -DCIVETWEB_ENABLE_CXX=on
        -DCIVETWEB_ENABLE_SERVER_EXECUTABLE=off
        -DCIVETWEB_ENABLE_SSL_DYNAMIC_LOADING=off
        -DCIVETWEB_SERVE_NO_FILES=on
        -DCMAKE_INSTALL_PREFIX=${CIVETWEB_SRC}/install
        BUILD_BYPRODUCTS ${CIVETWEB_LIB} ${CIVETWEB_CPP_LIB}
        PATCH_COMMAND patch -p1 -i ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/civetweb/patch/civetweb.patch)