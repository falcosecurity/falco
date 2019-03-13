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
#
include_directories("${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp")
include_directories("${LUAJIT_INCLUDE}")

include_directories("${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap")
include_directories("${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp")
include_directories("${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig")
include_directories("${PROJECT_SOURCE_DIR}/userspace/engine")
include_directories("${PROJECT_BINARY_DIR}/userspace/falco")
include_directories("${CURL_INCLUDE_DIR}")
include_directories("${TBB_INCLUDE_DIR}")
include_directories("${NJSON_INCLUDE}")
include_directories("${YAMLCPP_INCLUDE_DIR}")
include_directories("${CIVETWEB_INCLUDE_DIR}")
include_directories("${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include")

configure_file("${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig/config_sysdig.h.in" config_sysdig.h)

add_executable(falco
	configuration.cpp
	logger.cpp
	falco_outputs.cpp
	event_drops.cpp
	statsfilewriter.cpp
	falco.cpp
	"${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig/fields_info.cpp"
	webserver.cpp)

target_link_libraries(falco falco_engine sinsp)
target_link_libraries(falco
        "${LIBYAML_LIB}"
	"${YAMLCPP_LIB}"
	"${CIVETWEB_LIB}")

configure_file(config_falco.h.in config_falco.h)

add_custom_command(TARGET falco
	COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/verify_engine_fields.sh ${CMAKE_SOURCE_DIR}
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	COMMENT "Comparing engine fields checksum in falco_engine.h to actual fields"
	)

# add_custom_target(verify_engine_fields
# 	DEPENDS verify_engine_fields.sh falco_engine.h)

# add_dependencies(verify_engine_fields falco)

install(TARGETS falco DESTINATION ${FALCO_BIN_DIR})
install(DIRECTORY lua
	DESTINATION ${FALCO_SHARE_DIR}
	FILES_MATCHING PATTERN *.lua)
