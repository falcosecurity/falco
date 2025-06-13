# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2025 The Falco Authors.
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

option(USE_BUNDLED_JEMALLOC "Use bundled jemalloc allocator" ${USE_BUNDLED_DEPS})

if(JEMALLOC_INCLUDE)
	# we already have JEMALLOC
elseif(NOT USE_BUNDLED_JEMALLOC)
	find_path(JEMALLOC_INCLUDE jemalloc/jemalloc.h)
	set(JEMALLOC_INCLUDE ${JEMALLOC_INCLUDE}/jemalloc)
	if(BUILD_SHARED_LIBS)
		set(JEMALLOC_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
	else()
		set(JEMALLOC_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
	endif()
	find_library(MALLOC_LIB NAMES libjemalloc${JEMALLOC_LIB_SUFFIX})
	if(MALLOC_LIB)
		message(STATUS "Found system jemalloc: include: ${JEMALLOC_INCLUDE}, lib: ${MALLOC_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system jemalloc")
	endif()
else()
	if(BUILD_SHARED_LIBS)
		set(JEMALLOC_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
	else()
		set(JEMALLOC_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
	endif()
	set(JEMALLOC_SRC "${PROJECT_BINARY_DIR}/jemalloc-prefix/src")
	set(MALLOC_LIB "${JEMALLOC_SRC}/malloc/lib/libjemalloc${JEMALLOC_LIB_SUFFIX}")
	set(JEMALLOC_INCLUDE "${JEMALLOC_SRC}/malloc/include/jemalloc")
	if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
		set(JEMALLOC_ARCH_SPECIFIC_CONFIGURE_ARGS --with-lg-page=14)
	else()
		set(JEMALLOC_ARCH_SPECIFIC_CONFIGURE_ARGS "")
	endif()
	ExternalProject_Add(
		malloc
		PREFIX "${PROJECT_BINARY_DIR}/jemalloc-prefix"
		URL "https://github.com/jemalloc/jemalloc/archive/refs/tags/5.3.0.tar.gz"
		URL_HASH "SHA256=ef6f74fd45e95ee4ef7f9e19ebe5b075ca6b7fbe0140612b2a161abafb7ee179"
		CONFIGURE_COMMAND ./autogen.sh --enable-prof --disable-libdl
						  ${JEMALLOC_ARCH_SPECIFIC_CONFIGURE_ARGS}
		BUILD_IN_SOURCE 1
		BUILD_COMMAND make build_lib_static
		INSTALL_COMMAND ""
		UPDATE_COMMAND ""
		BUILD_BYPRODUCTS ${MALLOC_LIB}
	)
	install(
		FILES "${MALLOC_LIB}"
		DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
		COMPONENT "libs-deps"
	)
endif()

# We add a custom target, in this way we can always depend on `jemalloc` without distinguishing
# between "bundled" and "not-bundled" case
if(NOT TARGET malloc)
	add_custom_target(malloc)
endif()

include_directories(${JEMALLOC_INCLUDE})
add_compile_definitions(HAS_JEMALLOC)
