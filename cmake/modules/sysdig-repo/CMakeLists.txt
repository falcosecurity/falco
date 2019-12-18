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
cmake_minimum_required(VERSION 3.5.1)

project(sysdig-repo NONE)

include(ExternalProject)

# The sysdig git reference (branch name, commit hash, or tag)

# set(SYSDIG_VERSION falco/${FALCO_VERSION_MAJOR}.${FALCO_VERSION_MINOR}.${FALCO_VERSION_PATCH}")

# todo(leodido, fntlnz) > use this line above when FALCO_VERSION variable is ok (PR 872)
if(NOT SYSDIG_VERSION)
  set(SYSDIG_VERSION "dev")
endif()

ExternalProject_Add(
  sysdig
  URL "https://github.com/draios/sysdig/archive/${SYSDIG_VERSION}.tar.gz"
  URL_HASH SHA256=bd09607aa8beb863db07e695863f7dc543e2d39e7153005759d26a340ff66fa5
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
  TEST_COMMAND "")
