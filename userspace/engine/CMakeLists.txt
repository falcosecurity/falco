#
# Copyright (C) 2016-2018 Draios Inc dba Sysdig.
#
# This file is part of falco .
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if(NOT SYSDIG_DIR)
	set(SYSDIG_DIR "${PROJECT_SOURCE_DIR}/../sysdig")
endif()

set(FALCO_ENGINE_SOURCE_FILES
	rules.cpp
	falco_common.cpp
	falco_engine.cpp
	json_evt.cpp
	k8s_psp.cpp
	ruleset.cpp
	token_bucket.cpp
	formats.cpp)

add_library(falco_engine STATIC ${FALCO_ENGINE_SOURCE_FILES})

target_include_directories(falco_engine PUBLIC
	"${INJA_INCLUDE}"
	"${LUAJIT_INCLUDE}"
	"${NJSON_INCLUDE}"
	"${YAMLCPP_INCLUDE_DIR}"
	"${CURL_INCLUDE_DIR}"
	"${TBB_INCLUDE_DIR}"
	"${SYSDIG_DIR}/userspace/libsinsp/third-party/jsoncpp"
	"${SYSDIG_DIR}/userspace/libscap"
	"${SYSDIG_DIR}/userspace/libsinsp"
	"${PROJECT_BINARY_DIR}/userspace/engine"
	)

target_link_libraries(falco_engine
  "${FALCO_SINSP_LIBRARY}"
  "${LPEG_LIB}"
  "${LYAML_LIB}"
  "${LIBYAML_LIB}")

configure_file(config_falco_engine.h.in config_falco_engine.h)

if(DEFINED FALCO_COMPONENT)
install(DIRECTORY lua
	DESTINATION "${FALCO_SHARE_DIR}"
	COMPONENT "${FALCO_COMPONENT}"
	FILES_MATCHING PATTERN *.lua)
else()
install(DIRECTORY lua
	DESTINATION "${FALCO_SHARE_DIR}"
	FILES_MATCHING PATTERN *.lua)
endif()
