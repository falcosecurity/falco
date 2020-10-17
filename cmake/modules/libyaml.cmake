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

set(LIBYAML_SRC "${PROJECT_BINARY_DIR}/libyaml-prefix/src/libyaml")
set(LIBYAML_INSTALL_DIR "${LIBYAML_SRC}/target")
message(STATUS "Using bundled libyaml in '${LIBYAML_SRC}'")
set(LIBYAML_LIB "${LIBYAML_SRC}/src/.libs/libyaml.a")
ExternalProject_Add(
libyaml
URL "https://github.com/yaml/libyaml/releases/download/0.2.5/yaml-0.2.5.tar.gz"
URL_HASH "SHA256=c642ae9b75fee120b2d96c712538bd2cf283228d2337df2cf2988e3c02678ef4"
CONFIGURE_COMMAND ./configure --prefix=${LIBYAML_INSTALL_DIR} CFLAGS=-fPIC CPPFLAGS=-fPIC --enable-static=true --enable-shared=false
BUILD_COMMAND ${CMD_MAKE} 
BUILD_IN_SOURCE 1
INSTALL_COMMAND ${CMD_MAKE} install)

