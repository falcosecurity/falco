# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under
# the License.
#

option(USE_BUNDLED_CARES "Enable building of the bundled c-ares" ${USE_BUNDLED_DEPS})

if(CARES_INCLUDE)
	# we already have c-ares
elseif(NOT USE_BUNDLED_CARES)
	find_path(CARES_INCLUDE NAMES cares/ares.h ares.h)
	find_library(CARES_LIB NAMES cares)
	if(CARES_INCLUDE AND CARES_LIB)
		message(STATUS "Found c-ares: include: ${CARES_INCLUDE}, lib: ${CARES_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system c-ares")
	endif()
else()
	if(BUILD_SHARED_LIBS)
		set(CARES_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
		set(CARES_STATIC_OPTION "Off")
	else()
		set(CARES_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
		set(CARES_STATIC_OPTION "On")
	endif()
	set(CARES_SRC "${PROJECT_BINARY_DIR}/c-ares-prefix/src/c-ares")
	set(CARES_INCLUDE "${CARES_SRC}/include/")
	set(CARES_LIB "${CARES_SRC}/lib/libcares${CARES_LIB_SUFFIX}")

	if(NOT TARGET c-ares)
		message(STATUS "Using bundled c-ares in '${CARES_SRC}'")
		ExternalProject_Add(
			c-ares
			PREFIX "${PROJECT_BINARY_DIR}/c-ares-prefix"
			URL "https://github.com/c-ares/c-ares/releases/download/v1.33.1/c-ares-1.33.1.tar.gz"
			URL_HASH "SHA256=06869824094745872fa26efd4c48e622b9bd82a89ef0ce693dc682a23604f415"
			BUILD_IN_SOURCE 1
			CMAKE_ARGS -DCMAKE_POLICY_DEFAULT_CMP0091:STRING=NEW
					   -DCMAKE_MSVC_RUNTIME_LIBRARY=${CMAKE_MSVC_RUNTIME_LIBRARY}
					   -DCMAKE_INSTALL_LIBDIR=lib
					   -DCARES_SHARED=${BUILD_SHARED_LIBS}
					   -DCARES_STATIC=${CARES_STATIC_OPTION}
					   -DCARES_STATIC_PIC=${ENABLE_PIC}
					   -DCARES_BUILD_TOOLS=Off
					   -DCARES_INSTALL=Off
					   -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
			BUILD_BYPRODUCTS ${CARES_INCLUDE} ${CARES_LIB}
			INSTALL_COMMAND ""
		)
		install(
			FILES "${CARES_LIB}"
			DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps"
		)
		install(
			DIRECTORY "${CARES_INCLUDE}"
			DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps"
		)
	endif()

endif()

if(NOT TARGET c-ares)
	add_custom_target(c-ares)
endif()

include_directories("${CARES_INCLUDE}")
