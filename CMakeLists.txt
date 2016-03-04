cmake_minimum_required(VERSION 2.6)

project(digwatch)

set(DRAIOS_DEBUG_FLAGS "-D_DEBUG")
#set(DRAIOS_FEATURE_FLAGS "-DPPM_ENABLE_SENTINEL")

set(CMAKE_C_FLAGS "-Wall -ggdb ${DRAIOS_FEATURE_FLAGS}")
set(CMAKE_CXX_FLAGS "-Wall -ggdb --std=c++0x ${DRAIOS_FEATURE_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")
# Add "-fno-inline -fno-omit-frame-pointer" for perf
set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")
add_definitions(-DHAS_CAPTURE)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(KBUILD_FLAGS "${DRAIOS_DEBUG_FLAGS} ${DRAIOS_FEATURE_FLAGS}")
else()
	set(KBUILD_FLAGS "${DRAIOS_FEATURE_FLAGS}")
endif()

set(PACKAGE_NAME "draios-digwatch")

add_definitions(-DK8S_DISABLE_THREAD)

set(SYSDIG_DIR ${PROJECT_SOURCE_DIR}/../sysdig)

add_subdirectory(${SYSDIG_DIR} ${PROJECT_BINARY_DIR}/sysdig)

set(CURL_BUNDLE_DIR "${sysdig_BINARY_DIR}/curl-prefix/src/curl")
set(CURL_INCLUDE_DIR "${CURL_BUNDLE_DIR}/include/")
set(CURL_LIBRARIES "${CURL_BUNDLE_DIR}/lib/.libs/libcurl.a")

set(LUAJIT_INCLUDE_DIR "${sysdig_BINARY_DIR}/luajit-prefix/src/luajit/src")


message(STATUS "Using bundled curl in '${CURL_BUNDLE_DIR}'")
message(STATUS "Using SSL for curl in '${CURL_SSL_OPTION}'")



add_subdirectory(userspace/digwatch)

