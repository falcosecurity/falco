# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
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

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT FALCO_EXTRA_DEBUG_FLAGS)
  set(FALCO_EXTRA_DEBUG_FLAGS "-D_DEBUG")
endif()

string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE)
if(CMAKE_BUILD_TYPE STREQUAL "debug")
  set(KBUILD_FLAGS "${FALCO_EXTRA_DEBUG_FLAGS} ${FALCO_EXTRA_FEATURE_FLAGS}")
else()
  set(CMAKE_BUILD_TYPE "release")
  set(KBUILD_FLAGS "${FALCO_EXTRA_FEATURE_FLAGS}")
  add_definitions(-DBUILD_TYPE_RELEASE)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

if(MINIMAL_BUILD)
  set(MINIMAL_BUILD_FLAGS "-DMINIMAL_BUILD")
endif()

if(MUSL_OPTIMIZED_BUILD)
  set(MUSL_FLAGS "-static -Os -fPIE -pie")
  add_definitions(-DMUSL_OPTIMIZED)
endif()

# explicitly set hardening flags
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(FALCO_SECURITY_FLAGS "")
if(LINUX)
  set(FALCO_SECURITY_FLAGS "${FALCO_SECURITY_FLAGS} -fstack-protector-strong")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro,-z,now")
endif()


if(NOT MSVC)

	if(CMAKE_BUILD_TYPE STREQUAL "release")
		set(FALCO_SECURITY_FLAGS "${FALCO_SECURITY_FLAGS} -D_FORTIFY_SOURCE=2")
	endif()

	set(CMAKE_COMMON_FLAGS "${FALCO_SECURITY_FLAGS} -Wall -ggdb ${FALCO_EXTRA_FEATURE_FLAGS} ${MINIMAL_BUILD_FLAGS} ${MUSL_FLAGS}")

	if(BUILD_WARNINGS_AS_ERRORS)
		set(CMAKE_SUPPRESSED_WARNINGS
			"-Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set-variable -Wno-missing-field-initializers -Wno-sign-compare -Wno-type-limits -Wno-implicit-fallthrough -Wno-format-truncation -Wno-stringop-truncation -Wno-stringop-overflow -Wno-restrict"
		)
		set(CMAKE_COMPILE_WARNING_AS_ERROR ON)
		set(CMAKE_COMMON_FLAGS "${CMAKE_COMMON_FLAGS} -Wextra ${CMAKE_SUPPRESSED_WARNINGS}")
	endif()

	set(CMAKE_C_FLAGS "${CMAKE_COMMON_FLAGS}")
	set(CMAKE_CXX_FLAGS "-std=c++17 ${CMAKE_COMMON_FLAGS}")

	set(CMAKE_C_FLAGS_DEBUG "${FALCO_EXTRA_DEBUG_FLAGS}")
	set(CMAKE_CXX_FLAGS_DEBUG "${FALCO_EXTRA_DEBUG_FLAGS}")

	set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
	set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

else() # MSVC
	set(MINIMAL_BUILD ON)
	set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

	# The WIN32_LEAN_AND_MEAN define avoids possible macro pollution
	# when a libsinsp consumer includes the windows.h header.
	# See: https://stackoverflow.com/a/28380820

	add_compile_definitions(
		_HAS_STD_BYTE=0
		_CRT_SECURE_NO_WARNINGS
		WIN32
		MINIMAL_BUILD
		WIN32_LEAN_AND_MEAN
	)

	set(FALCOSECURITY_LIBS_COMMON_FLAGS "/EHsc /W3 /Zi /std:c++17")
	set(FALCOSECURITY_LIBS_DEBUG_FLAGS "/MTd /Od")
	set(FALCOSECURITY_LIBS_RELEASE_FLAGS "/MT")

	set(CMAKE_C_FLAGS "${FALCOSECURITY_LIBS_COMMON_FLAGS}")
	set(CMAKE_CXX_FLAGS "${FALCOSECURITY_LIBS_COMMON_FLAGS}")

	set(CMAKE_C_FLAGS_DEBUG "${FALCOSECURITY_LIBS_DEBUG_FLAGS}")
	set(CMAKE_CXX_FLAGS_DEBUG "${FALCOSECURITY_LIBS_DEBUG_FLAGS}")

	set(CMAKE_C_FLAGS_RELEASE "${FALCOSECURITY_LIBS_RELEASE_FLAGS}")
	set(CMAKE_CXX_FLAGS_RELEASE "${FALCOSECURITY_LIBS_RELEASE_FLAGS}")

endif()
