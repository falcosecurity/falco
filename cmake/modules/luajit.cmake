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

set(LUAJIT_SRC "${PROJECT_BINARY_DIR}/luajit-prefix/src/luajit/src")
message(STATUS "Using bundled LuaJIT in '${LUAJIT_SRC}'")
set(LUAJIT_INCLUDE "${LUAJIT_SRC}")
set(LUAJIT_LIB "${LUAJIT_SRC}/libluajit.a")
externalproject_add(
  luajit
  GIT_REPOSITORY "https://github.com/LuaJIT/LuaJIT"
  GIT_TAG "1d8b747c161db457e032a023ebbff511f5de5ec2"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ${CMD_MAKE}
  BUILD_IN_SOURCE 1
  BUILD_BYPRODUCTS ${LUAJIT_LIB}
  INSTALL_COMMAND ""
)
