#
# Copyright (C) 2013-2018 Draios Inc dba Sysdig.
#
# This file is part of sysdig .
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
include_directories("${JSONCPP_INCLUDE}")

if(NOT WIN32)
	include_directories("${TBB_INCLUDE_DIR}")
	include_directories("${CURL_INCLUDE_DIR}")
	include_directories("${CURSES_INCLUDE_DIR}")
endif()

include_directories("${PROJECT_SOURCE_DIR}/common")
include_directories("${PROJECT_SOURCE_DIR}/userspace/libscap")
include_directories("${PROJECT_SOURCE_DIR}/userspace/libsinsp")
include_directories("${PROJECT_BINARY_DIR}/userspace/sysdig")
include_directories(.)

if(NOT WIN32)
	set(SOURCE_FILES
		fields_info.cpp
		sysdig.cpp)

	set(SOURCE_FILES_CSYSDIG
		fields_info.cpp
		csysdig.cpp)
else()
	set(SOURCE_FILES
		fields_info.cpp
		sysdig.cpp
		win32/getopt.c)

	set(SOURCE_FILES_CSYSDIG
		fields_info.cpp
		csysdig.cpp
		win32/getopt.c)
endif()

add_executable(sysdig ${SOURCE_FILES})
add_executable(csysdig ${SOURCE_FILES_CSYSDIG})

if(NOT WIN32)
	include_directories(${PROJECT_BINARY_DIR}/driver/src)
	target_link_libraries(sysdig
		sinsp)

	if(USE_BUNDLED_NCURSES)
		add_dependencies(csysdig ncurses)
	endif()

	target_link_libraries(csysdig
		sinsp
		"${CURSES_LIBRARIES}")

	add_subdirectory(man)

	install(TARGETS sysdig 
		DESTINATION bin)

	install(TARGETS csysdig 
		DESTINATION bin)

	install(DIRECTORY chisels
		DESTINATION share/sysdig)

	file(COPY chisels
		DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

else()

	target_link_libraries(sysdig
		sinsp)

	target_link_libraries(csysdig
		sinsp)

	target_link_libraries(sysdig odbc32.lib odbccp32.lib)

	target_link_libraries(csysdig odbc32.lib odbccp32.lib)

	add_custom_command(TARGET sysdig POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			"${LUAJIT_SRC}/lua51.dll"
			"${PROJECT_BINARY_DIR}/$(Configuration)/lua51.dll")

	add_custom_command(TARGET sysdig POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			"${ZLIB_INCLUDE}/zlib1.dll"
			"${PROJECT_BINARY_DIR}/$(Configuration)/")

	add_custom_command(TARGET sysdig POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_directory
			"${PROJECT_SOURCE_DIR}/userspace/sysdig/chisels"
			"${PROJECT_BINARY_DIR}/$(Configuration)/chisels")

	add_custom_command(TARGET sysdig POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			$<TARGET_FILE:sysdig>
			"${PROJECT_BINARY_DIR}/$(Configuration)/sysdig.exe")

	add_custom_command(TARGET csysdig POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			$<TARGET_FILE:csysdig>
			"${PROJECT_BINARY_DIR}/$(Configuration)/csysdig.exe")

endif()

configure_file(config_sysdig.h.in config_sysdig.h)
