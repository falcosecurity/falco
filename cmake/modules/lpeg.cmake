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

set(LPEG_SRC "${PROJECT_BINARY_DIR}/lpeg-prefix/src/lpeg")
set(LPEG_LIB "${PROJECT_BINARY_DIR}/lpeg-prefix/src/lpeg/build/lpeg.a")
message(STATUS "Using bundled lpeg in '${LPEG_SRC}'")
set(LPEG_DEPENDENCIES "")
list(APPEND LPEG_DEPENDENCIES "luajit")
ExternalProject_Add(
  lpeg
  DEPENDS ${LPEG_DEPENDENCIES}
  URL "http://www.inf.puc-rio.br/~roberto/lpeg/lpeg-1.0.2.tar.gz"
  URL_HASH "SHA256=48d66576051b6c78388faad09b70493093264588fcd0f258ddaab1cdd4a15ffe"
  BUILD_COMMAND LUA_INCLUDE=${LUAJIT_INCLUDE} "${PROJECT_SOURCE_DIR}/scripts/build-lpeg.sh" "${LPEG_SRC}/build"
  BUILD_IN_SOURCE 1
  BUILD_BYPRODUCTS ${LPEG_LIB}
  CONFIGURE_COMMAND ""
  INSTALL_COMMAND "")
