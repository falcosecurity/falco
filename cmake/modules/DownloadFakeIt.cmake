#
# Copyright (C) 2019 The Falco Authors.
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

set(FAKEIT_INCLUDE ${CMAKE_BINARY_DIR}/fakeit-prefix/include)

set(FAKEIT_EXTERNAL_URL URL https://github.com/eranpeer/fakeit/archive/2.0.5.tar.gz URL_HASH
                        SHA256=298539c773baca6ecbc28914306bba19d1008e098f8adc3ad3bb00e993ecdf15)

ExternalProject_Add(
  fakeit-external
  PREFIX ${CMAKE_BINARY_DIR}/fakeit-prefix
  ${FAKEIT_EXTERNAL_URL}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND
    ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/fakeit-prefix/src/fakeit-external/single_header/catch/fakeit.hpp
    ${FAKEIT_INCLUDE}/fakeit.hpp)
