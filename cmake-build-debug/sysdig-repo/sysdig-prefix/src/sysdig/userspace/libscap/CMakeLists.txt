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
include_directories("${PROJECT_SOURCE_DIR}/common")
include_directories("${ZLIB_INCLUDE}")
if(CYGWIN)
include_directories("${WIN_HAL_INCLUDE}")
endif()

list(APPEND targetfiles
	scap.c
	scap_event.c
	scap_fds.c
	scap_iflist.c
	scap_savefile.c
	scap_procs.c
	scap_userlist.c
	syscall_info_table.c
	../../driver/dynamic_params_table.c
	../../driver/event_table.c
	../../driver/flags_table.c)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	list(APPEND targetfiles
		scap_bpf.c
		../../driver/syscall_table.c
		../../driver/fillers_table.c)

    include_directories(${PROJECT_BINARY_DIR}/driver/src)
endif()

if(CYGWIN)
	list(APPEND targetfiles
		windows_hal.c)
endif()

add_library(scap STATIC
	${targetfiles})

if(USE_BUNDLED_ZLIB)
	add_dependencies(scap zlib)
endif()

if (CMAKE_SYSTEM_NAME MATCHES "SunOS")
	target_link_libraries(scap
		socket nsl)
elseif (CMAKE_SYSTEM_NAME MATCHES "Linux")
	target_link_libraries(scap
		elf
		rt)
elseif (WIN32)
	target_link_libraries(scap
		Ws2_32.lib)
elseif (CYGWIN)
	target_link_libraries(scap
		/lib/w32api/libpsapi.a
		${WIN_HAL_LIB}/dragent_win_hal.lib)
endif()

target_link_libraries(scap
	"${ZLIB_LIB}")

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    option(BUILD_LIBSCAP_EXAMPLES "Build libscap examples" ON)

    if (BUILD_LIBSCAP_EXAMPLES)
        add_subdirectory(examples/01-open)
        add_subdirectory(examples/02-validatebuffer)
    endif()

	include(FindMakedev)
endif()
