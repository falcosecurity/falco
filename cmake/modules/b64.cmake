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

set(B64_SRC "${PROJECT_BINARY_DIR}/b64-prefix/src/b64")
message(STATUS "Using bundled b64 in '${B64_SRC}'")
set(B64_INCLUDE "${B64_SRC}/include")
set(B64_LIB "${B64_SRC}/src/libb64.a")
externalproject_add(
  b64
  URL "https://github.com/libb64/libb64/archive/ce864b17ea0e24a91e77c7dd3eb2d1ac4175b3f0.tar.gz"
  URL_HASH "SHA256=d07173e66f435e5c77dbf81bd9313f8d0e4a3b4edd4105a62f4f8132ba932811"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ${CMD_MAKE}
  BUILD_IN_SOURCE 1
  BUILD_BYPRODUCTS ${B64_LIB}
  INSTALL_COMMAND ""
)
