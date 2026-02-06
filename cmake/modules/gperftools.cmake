# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 The Falco Authors.
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

# gperftools CPU profiler support This module provides: GPERFTOOLS_INCLUDE_DIR (include directory)
# and GPERFTOOLS_PROFILER_LIB (the profiler library path)

option(USE_BUNDLED_GPERFTOOLS "Build gperftools from source" ${USE_BUNDLED_DEPS})

if(GPERFTOOLS_INCLUDE_DIR)
	# Already have gperftools configured
elseif(NOT USE_BUNDLED_GPERFTOOLS)
	# Use system gperftools
	find_path(
		GPERFTOOLS_INCLUDE_DIR
		NAMES gperftools/profiler.h
		PATHS /usr/include /usr/local/include
	)

	find_library(
		GPERFTOOLS_PROFILER_LIB
		NAMES profiler
		PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu
	)

	if(GPERFTOOLS_INCLUDE_DIR AND GPERFTOOLS_PROFILER_LIB)
		message(
			STATUS
				"Found system gperftools: include: ${GPERFTOOLS_INCLUDE_DIR}, lib: ${GPERFTOOLS_PROFILER_LIB}"
		)
	else()
		message(
			FATAL_ERROR
				"Couldn't find system gperftools. Install it or use -DUSE_BUNDLED_GPERFTOOLS=ON\n"
				"  Ubuntu/Debian: sudo apt-get install libgoogle-perftools-dev\n"
				"  Fedora/RHEL:   sudo dnf install gperftools-devel\n"
				"  macOS:         brew install gperftools"
		)
	endif()
else()
	# Build gperftools from source
	set(GPERFTOOLS_SRC "${PROJECT_BINARY_DIR}/gperftools-prefix/src/gperftools")
	set(GPERFTOOLS_INCLUDE_DIR "${GPERFTOOLS_SRC}/src")

	if(BUILD_SHARED_LIBS)
		set(GPERFTOOLS_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
	else()
		set(GPERFTOOLS_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
	endif()

	# The library is built in .libs subdirectory
	set(GPERFTOOLS_PROFILER_LIB "${GPERFTOOLS_SRC}/.libs/libprofiler${GPERFTOOLS_LIB_SUFFIX}")

	# gperftools version 2.15 (latest stable as of 2024)
	set(GPERFTOOLS_VERSION "2.15")
	set(GPERFTOOLS_URL
		"https://github.com/gperftools/gperftools/releases/download/gperftools-${GPERFTOOLS_VERSION}/gperftools-${GPERFTOOLS_VERSION}.tar.gz"
	)
	set(GPERFTOOLS_URL_HASH
		"SHA256=c69fef855628c81ef56f12e3c58f2b7ce1f326c0a1fe783e5cae0b88cbbe9a80"
	)

	message(STATUS "Building gperftools ${GPERFTOOLS_VERSION} from source")

	# Configure options for gperftools
	set(GPERFTOOLS_CONFIGURE_ARGS --enable-cpu-profiler --disable-heap-profiler
								  --disable-heap-checker --disable-debugalloc
	)

	# Check if libunwind is available for better stack traces
	find_library(LIBUNWIND_LIBRARY NAMES unwind)
	if(LIBUNWIND_LIBRARY)
		list(APPEND GPERFTOOLS_CONFIGURE_ARGS --enable-libunwind)
		message(STATUS "gperftools: libunwind found, enabling for better stack traces")
	else()
		list(APPEND GPERFTOOLS_CONFIGURE_ARGS --disable-libunwind)
		message(STATUS "gperftools: libunwind not found, using frame pointers for stack traces")
	endif()

	ExternalProject_Add(
		gperftools
		PREFIX "${PROJECT_BINARY_DIR}/gperftools-prefix"
		URL "${GPERFTOOLS_URL}"
		URL_HASH "${GPERFTOOLS_URL_HASH}"
		CONFIGURE_COMMAND <SOURCE_DIR>/configure ${GPERFTOOLS_CONFIGURE_ARGS}
		BUILD_COMMAND ${CMD_MAKE} ${PROCESSOUR_COUNT_MAKE_FLAG}
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND ""
		UPDATE_COMMAND ""
		BUILD_BYPRODUCTS ${GPERFTOOLS_PROFILER_LIB}
	)

	install(
		FILES "${GPERFTOOLS_PROFILER_LIB}"
		DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
		COMPONENT "libs-deps"
		OPTIONAL
	)
endif()

# Create a custom target so we can always depend on 'gperftools' regardless of bundled/system
if(NOT TARGET gperftools)
	add_custom_target(gperftools)
endif()

# Add include directory globally
include_directories(${GPERFTOOLS_INCLUDE_DIR})

# Add compile definition so code can detect profiling support
add_compile_definitions(HAS_GPERFTOOLS)

# Wrap the profiler library with --whole-archive to ensure the profiler's initialization code is
# linked even though we don't call ProfilerStart() directly. This is required for the CPUPROFILE
# environment variable to work.
set(GPERFTOOLS_PROFILER_LIB "-Wl,--whole-archive" "${GPERFTOOLS_PROFILER_LIB}"
							"-Wl,--no-whole-archive"
)

message(STATUS "gperftools CPU profiler enabled")
message(STATUS "  Include dir: ${GPERFTOOLS_INCLUDE_DIR}")
message(STATUS "  Library: ${GPERFTOOLS_PROFILER_LIB}")
