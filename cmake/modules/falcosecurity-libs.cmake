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

set(FALCOSECURITY_LIBS_CMAKE_SOURCE_DIR
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/falcosecurity-libs-repo"
)
set(FALCOSECURITY_LIBS_CMAKE_WORKING_DIR "${CMAKE_BINARY_DIR}/falcosecurity-libs-repo")

file(MAKE_DIRECTORY ${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR})

# explicitly disable the bundled driver, since we pull it separately
set(USE_BUNDLED_DRIVER
	OFF
	CACHE BOOL ""
)

if(FALCOSECURITY_LIBS_SOURCE_DIR)
	set(FALCOSECURITY_LIBS_VERSION "0.0.0-local")
	message(STATUS "Using local version of falcosecurity/libs: '${FALCOSECURITY_LIBS_SOURCE_DIR}'")
else()
	# FALCOSECURITY_LIBS_REPO accepts a repository name (<org name>/<repo name>) alternative to the
	# falcosecurity/libs repository. In case you want to test against a fork of falcosecurity/libs
	# just pass the variable - ie., `cmake -DFALCOSECURITY_LIBS_REPO=<your-gh-handle>/libs ..`
	if(NOT FALCOSECURITY_LIBS_REPO)
		set(FALCOSECURITY_LIBS_REPO "falcosecurity/libs")
	endif()

	# FALCOSECURITY_LIBS_VERSION accepts a git reference (branch name, commit hash, or tag) to the
	# falcosecurity/libs repository. In case you want to test against another falcosecurity/libs
	# version (or branch, or commit) just pass the variable - ie., `cmake
	# -DFALCOSECURITY_LIBS_VERSION=dev ..`
	if(NOT FALCOSECURITY_LIBS_VERSION)
		set(FALCOSECURITY_LIBS_VERSION "dee5c26a02eb3967845cf81e7148d2def41d6c81")
		set(FALCOSECURITY_LIBS_CHECKSUM
			"SHA256=5475cd1f9f13788eb80ad03a2e3bff8f69c5a20068c0455577ce072d00962cce"
		)
	endif()

	# cd /path/to/build && cmake /path/to/source
	execute_process(
		COMMAND
			"${CMAKE_COMMAND}" -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
			-DFALCOSECURITY_LIBS_REPO=${FALCOSECURITY_LIBS_REPO}
			-DFALCOSECURITY_LIBS_VERSION=${FALCOSECURITY_LIBS_VERSION}
			-DFALCOSECURITY_LIBS_CHECKSUM=${FALCOSECURITY_LIBS_CHECKSUM}
			${FALCOSECURITY_LIBS_CMAKE_SOURCE_DIR}
		WORKING_DIRECTORY ${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR}
	)

	# cmake --build .
	execute_process(
		COMMAND "${CMAKE_COMMAND}" --build .
		WORKING_DIRECTORY "${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR}"
	)
	set(FALCOSECURITY_LIBS_SOURCE_DIR
		"${FALCOSECURITY_LIBS_CMAKE_WORKING_DIR}/falcosecurity-libs-prefix/src/falcosecurity-libs"
	)
endif()

set(LIBS_PACKAGE_NAME "falcosecurity")

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	add_definitions(-D_GNU_SOURCE)
endif()

if(MUSL_OPTIMIZED_BUILD)
	add_definitions(-DMUSL_OPTIMIZED)
endif()

set(SCAP_HOST_ROOT_ENV_VAR_NAME "HOST_ROOT")
set(SCAP_HOSTNAME_ENV_VAR "FALCO_HOSTNAME")
set(SINSP_AGENT_CGROUP_MEM_PATH_ENV_VAR "FALCO_CGROUP_MEM_PATH")

if(NOT LIBS_DIR)
	set(LIBS_DIR "${FALCOSECURITY_LIBS_SOURCE_DIR}")
endif()

# configure gVisor support
set(BUILD_LIBSCAP_GVISOR
	${BUILD_FALCO_GVISOR}
	CACHE BOOL ""
)

# configure modern BPF support
set(BUILD_LIBSCAP_MODERN_BPF
	${BUILD_FALCO_MODERN_BPF}
	CACHE BOOL ""
)

# explicitly disable the tests/examples of this dependency
set(CREATE_TEST_TARGETS
	OFF
	CACHE BOOL ""
)
set(BUILD_LIBSCAP_EXAMPLES
	OFF
	CACHE BOOL ""
)

set(USE_BUNDLED_TBB
	ON
	CACHE BOOL ""
)
set(USE_BUNDLED_JSONCPP
	ON
	CACHE BOOL ""
)
set(USE_BUNDLED_VALIJSON
	ON
	CACHE BOOL ""
)
set(USE_BUNDLED_RE2
	ON
	CACHE BOOL ""
)
set(USE_BUNDLED_UTHASH
	ON
	CACHE BOOL ""
)
if(USE_DYNAMIC_LIBELF)
	set(USE_BUNDLED_LIBELF
		OFF
		CACHE BOOL ""
	)
	set(USE_SHARED_LIBELF
		ON
		CACHE BOOL ""
	)
endif()

list(APPEND CMAKE_MODULE_PATH "${FALCOSECURITY_LIBS_SOURCE_DIR}/cmake/modules")

include(CheckSymbolExists)
check_symbol_exists(strlcpy "string.h" HAVE_STRLCPY)

if(HAVE_STRLCPY)
	message(
		STATUS
			"Existing strlcpy and strlcat found, will *not* use local definition by setting -DHAVE_STRLCPY and -DHAVE_STRLCAT."
	)
	add_definitions(-DHAVE_STRLCPY)
	add_definitions(-DHAVE_STRLCAT)
else()
	message(STATUS "No strlcpy and strlcat found, will use local definition")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	include(driver)
endif()
include(libscap)
include(libsinsp)
