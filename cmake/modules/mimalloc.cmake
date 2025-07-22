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

option(USE_BUNDLED_MIMALLOC "Use bundled mimalloc (microsoft) allocator" ${USE_BUNDLED_DEPS})

if(MIMALLOC_INCLUDE)
	# we already have MIMALLOC
elseif(NOT USE_BUNDLED_MIMALLOC)
	find_path(MIMALLOC_INCLUDE mimalloc/mimalloc.h)
	set(MIMALLOC_INCLUDE ${MIMALLOC_INCLUDE}/mimalloc)
	if(BUILD_SHARED_LIBS)
		set(MIMALLOC_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
	else()
		set(MIMALLOC_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
	endif()
	find_library(MALLOC_LIB NAMES libmimalloc${MIMALLOC_LIB_SUFFIX})
	if(MALLOC_LIB)
		message(STATUS "Found system mimalloc: include: ${MIMALLOC_INCLUDE}, lib: ${MALLOC_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system mimalloc")
	endif()
else()
	if(BUILD_SHARED_LIBS)
		set(BUILD_STATIC Off)
		set(MIMALLOC_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
	else()
		set(BUILD_STATIC On)
		set(MIMALLOC_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
	endif()
	set(MIMALLOC_SRC "${PROJECT_BINARY_DIR}/mimalloc-prefix/src")
	string(TOLOWER "${CMAKE_BUILD_TYPE}" _build_type)
	if(_build_type STREQUAL "debug")
		set(MIMALLOC_LIB_BASENAME "libmimalloc-debug")
	else()
		set(MIMALLOC_LIB_BASENAME "libmimalloc")
	endif()
	set(MALLOC_LIB "${MIMALLOC_SRC}/malloc-build/${MIMALLOC_LIB_BASENAME}${MIMALLOC_LIB_SUFFIX}")
	set(MIMALLOC_INCLUDE ${MIMALLOC_SRC}/malloc/include/)

	# To avoid recent clang versions complaining with "error: expansion of date or time macro is not
	# reproducible" while building mimalloc, we force-set both variables.
	string(TIMESTAMP DATE "%Y%m%d")
	string(TIMESTAMP TIME "%H:%M")
	set(MIMALLOC_EXTRA_CPPDEFS __DATE__="${DATE}",__TIME__="${TIME}")

	# We disable arch specific optimization because of issues with building with zig. Optimizations
	# would be only effective on arm64. See MI_NO_OPT_ARCH=On.
	ExternalProject_Add(
		malloc
		PREFIX "${PROJECT_BINARY_DIR}/mimalloc-prefix"
		URL "https://github.com/microsoft/mimalloc/archive/refs/tags/v3.1.5.tar.gz"
		URL_HASH "SHA256=1c6949032069d5ebea438ec5cedd602d06f40a92ddf0f0d9dcff0993e5f6635c"
		LIST_SEPARATOR "," # to pass MIMALLOC_EXTRA_CPPDEFS as list
		CMAKE_ARGS -DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
				   -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
				   -DMI_BUILD_SHARED=${BUILD_SHARED_LIBS}
				   -DMI_BUILD_STATIC=${BUILD_STATIC}
				   -DMI_BUILD_TESTS=Off
				   -DMI_BUILD_OBJECT=Off
				   -DMI_NO_OPT_ARCH=On
				   -DMI_EXTRA_CPPDEFS=${MIMALLOC_EXTRA_CPPDEFS}
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

# We add a custom target, in this way we can always depend on `mimalloc` without distinguishing
# between "bundled" and "not-bundled" case
if(NOT TARGET malloc)
	add_custom_target(malloc)
endif()

include_directories(${MIMALLOC_INCLUDE})
add_compile_definitions(HAS_MIMALLOC)
