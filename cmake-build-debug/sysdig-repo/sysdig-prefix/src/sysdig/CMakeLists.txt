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

# Prior to doing anything, we make sure that we aren't trying to
# run cmake in-tree. (see Issue 71: https://github.com/draios/sysdig/issues/71)
if(EXISTS CMakeLists.txt)
	message(FATAL_ERROR
		"Looks like you are trying to run cmake from the base sysdig source directory.\n"
		"** RUNNING CMAKE FROM THE BASE SYSDIG DIRECTORY WILL NOT WORK **\n"
		"To Fix:\n"
		" 1. Remove the CMakeCache.txt file in this directory. ex: rm CMakeCache.txt\n"
		" 2. Create a build directory from here. ex: mkdir build\n"
		" 3. cd into that directory. ex: cd build\n"
		" 4. Run cmake from the build directory. ex: cmake ..\n"
		" 5. Run make from the build directory. ex: make\n"
		"Full paste-able example:\n"
		"( rm -f CMakeCache.txt; mkdir build; cd build; cmake ..; make )\n"
		"The following wiki page has more information on manually building sysdig: http://bit.ly/1oJ84UI")
endif()

cmake_minimum_required(VERSION 2.8.2)

project(sysdig)

# Add path for custom CMake modules.
list(APPEND CMAKE_MODULE_PATH
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

if(NOT DEFINED SYSDIG_VERSION)
	set(SYSDIG_VERSION "0.1.1dev")
endif()

if(NOT DEFINED DIR_ETC)
	set(DIR_ETC "${CMAKE_INSTALL_PREFIX}/etc")
endif()

if(NOT CMAKE_BUILD_TYPE)
	SET(CMAKE_BUILD_TYPE Release)
endif()

set(PACKAGE_NAME "sysdig")

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")
add_definitions(-DK8S_DISABLE_THREAD)

option(BUILD_WARNINGS_AS_ERRORS "Enable building with -Wextra -Werror flags")

if(NOT WIN32)

	set(SYSDIG_DEBUG_FLAGS "-D_DEBUG")
	set(CMAKE_COMMON_FLAGS "-Wall -ggdb")

	if(BUILD_WARNINGS_AS_ERRORS)
		set(CMAKE_SUPPRESSED_WARNINGS "-Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -Wno-type-limits -Wno-implicit-fallthrough -Wno-format-truncation")
		set(CMAKE_COMMON_FLAGS "${CMAKE_COMMON_FLAGS} -Wextra -Werror ${CMAKE_SUPPRESSED_WARNINGS}")
	endif()

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_COMMON_FLAGS}")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_COMMON_FLAGS} -std=c++0x")

	set(CMAKE_C_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")
	set(CMAKE_CXX_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")

	set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
	set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

	if(CMAKE_SYSTEM_NAME MATCHES "Linux")
		if(CMAKE_BUILD_TYPE STREQUAL "Debug")
			set(KBUILD_FLAGS "${SYSDIG_DEBUG_FLAGS} ${SYSDIG_FEATURE_FLAGS}")
		else()
			set(KBUILD_FLAGS "${SYSDIG_FEATURE_FLAGS}")
		endif()

		if(NOT DEFINED PROBE_VERSION)
			set(PROBE_VERSION "${SYSDIG_VERSION}")
		endif()
		if(NOT DEFINED PROBE_NAME)
			set(PROBE_NAME "sysdig-probe")
		endif()

		if(NOT DEFINED PROBE_DEVICE_NAME)
			set(PROBE_DEVICE_NAME "sysdig")
		endif()

		add_subdirectory(driver)
		add_definitions(-DHAS_CAPTURE)
	endif()

	add_subdirectory(scripts)

	if(CMAKE_SYSTEM_NAME MATCHES "SunOS")
		set(CMD_MAKE gmake)
	else()
		set(CMD_MAKE make)
	endif()

else()

	set(SYSDIG_FLAGS_WIN "-D_CRT_SECURE_NO_WARNINGS -DWIN32 /EHsc /W3 /Zi")
	set(SYSDIG_FLAGS_WIN_DEBUG "/MTd /Od")
	set(SYSDIG_FLAGS_WIN_RELEASE "/MT")

	set(CMAKE_C_FLAGS "${SYSDIG_FLAGS_WIN}")
	set(CMAKE_CXX_FLAGS "${SYSDIG_FLAGS_WIN}")

	set(CMAKE_C_FLAGS_DEBUG "${SYSDIG_FLAGS_WIN_DEBUG}")
	set(CMAKE_CXX_FLAGS_DEBUG "${SYSDIG_FLAGS_WIN_DEBUG}")

	set(CMAKE_C_FLAGS_RELEASE "${SYSDIG_FLAGS_WIN_RELEASE}")
	set(CMAKE_CXX_FLAGS_RELEASE "${SYSDIG_FLAGS_WIN_RELEASE}")

endif()

if(APPLE)
	set(CMAKE_EXE_LINKER_FLAGS "-pagezero_size 10000 -image_base 100000000")
endif()

include(ExternalProject)

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

#
# LuaJIT
#
option(USE_BUNDLED_LUAJIT "Enable building of the bundled LuaJIT" ${USE_BUNDLED_DEPS})

if(NOT USE_BUNDLED_LUAJIT)
	find_path(LUAJIT_INCLUDE luajit.h PATH_SUFFIXES luajit-2.0 luajit)
	find_library(LUAJIT_LIB NAMES luajit luajit-5.1)
	if(LUAJIT_INCLUDE AND LUAJIT_LIB)
		message(STATUS "Found LuaJIT: include: ${LUAJIT_INCLUDE}, lib: ${LUAJIT_LIB}")
	else()
		# alternatively try stock Lua
		find_package(Lua51)
		set(LUAJIT_LIB ${LUA_LIBRARY})
		set(LUAJIT_INCLUDE ${LUA_INCLUDE_DIR})

		if(NOT ${LUA51_FOUND})
			message(FATAL_ERROR "Couldn't find system LuaJIT or Lua")
		endif()
	endif()
else()
	set(LUAJIT_SRC "${PROJECT_BINARY_DIR}/luajit-prefix/src/luajit/src")
	message(STATUS "Using bundled LuaJIT in '${LUAJIT_SRC}'")
	set(LUAJIT_INCLUDE "${LUAJIT_SRC}")
	if(NOT WIN32)
		set(LUAJIT_LIB "${LUAJIT_SRC}/libluajit.a")
 		if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "ppc64le")
		ExternalProject_Add(luajit
			GIT_REPOSITORY "https://github.com/moonjit/moonjit"
			GIT_TAG "2.1.2"
			PATCH_COMMAND sed -i "s/luaL_reg/luaL_Reg/g" ${PROJECT_SOURCE_DIR}/userspace/libsinsp/chisel.cpp && sed -i "s/luaL_reg/luaL_Reg/g" ${PROJECT_SOURCE_DIR}/userspace/libsinsp/lua_parser.cpp && sed -i "s/luaL_getn/lua_objlen /g" ${PROJECT_SOURCE_DIR}/userspace/libsinsp/lua_parser_api.cpp
			CONFIGURE_COMMAND ""
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${LUAJIT_LIB}
			INSTALL_COMMAND "")
		elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "s390x")
                ExternalProject_Add(luajit
                        GIT_REPOSITORY "https://github.com/linux-on-ibm-z/LuaJIT.git"
                        GIT_TAG "v2.1"
                        PATCH_COMMAND sed -i "s/luaL_reg/luaL_Reg/g" ${PROJECT_SOURCE_DIR}/userspace/libsinsp/chisel.cpp && sed -i "s/luaL_reg/luaL_Reg/g" ${PROJECT_SOURCE_DIR}/userspace/libsinsp/lua_parser.cpp && sed -i "s/luaL_getn/lua_objlen /g" ${PROJECT_SOURCE_DIR}/userspace/libsinsp/lua_parser_api.cpp
                        CONFIGURE_COMMAND ""
                        BUILD_COMMAND ${CMD_MAKE}
                        BUILD_IN_SOURCE 1
                        BUILD_BYPRODUCTS ${LUAJIT_LIB}
                        INSTALL_COMMAND "")		
		else()
		ExternalProject_Add(luajit
			URL "http://download.draios.com/dependencies/LuaJIT-2.0.3.tar.gz"
			URL_MD5 "f14e9104be513913810cd59c8c658dc0"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${LUAJIT_LIB}
			INSTALL_COMMAND "")
		endif()
	else()
		set(LUAJIT_LIB "${LUAJIT_SRC}/lua51.lib")
		ExternalProject_Add(luajit
			URL "http://download.draios.com/dependencies/LuaJIT-2.0.3.tar.gz"
			URL_MD5 "f14e9104be513913810cd59c8c658dc0"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND msvcbuild.bat
			BUILD_BYPRODUCTS ${LUAJIT_LIB}
			BINARY_DIR "${LUAJIT_SRC}"
			INSTALL_COMMAND "")
	endif()
endif()

#
# JsonCpp
#
option(USE_BUNDLED_JSONCPP "Enable building of the bundled jsoncpp" ${USE_BUNDLED_DEPS})

set(JSONCPP_SRC "${PROJECT_SOURCE_DIR}/userspace/libsinsp/third-party/jsoncpp")

if(NOT USE_BUNDLED_JSONCPP)
	find_path(JSONCPP_INCLUDE json/json.h PATH_SUFFIXES jsoncpp)
	find_library(JSONCPP_LIB NAMES jsoncpp)
	if(JSONCPP_INCLUDE AND JSONCPP_LIB)
		message(STATUS "Found jsoncpp: include: ${JSONCPP_INCLUDE}, lib: ${JSONCPP_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system jsoncpp")
	endif()
else()
	set(JSONCPP_INCLUDE "${JSONCPP_SRC}")
	set(JSONCPP_LIB_SRC "${JSONCPP_SRC}/jsoncpp.cpp")
	message(STATUS "Using bundled jsoncpp in '${JSONCPP_SRC}'")
endif()

#
# zlib
#
option(USE_BUNDLED_ZLIB "Enable building of the bundled zlib" ${USE_BUNDLED_DEPS})

if(NOT USE_BUNDLED_ZLIB)
	find_path(ZLIB_INCLUDE zlib.h PATH_SUFFIXES zlib)
	find_library(ZLIB_LIB NAMES z)
	if(ZLIB_INCLUDE AND ZLIB_LIB)
		message(STATUS "Found zlib: include: ${ZLIB_INCLUDE}, lib: ${ZLIB_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system zlib")
	endif()
else()
	set(ZLIB_SRC "${PROJECT_BINARY_DIR}/zlib-prefix/src/zlib")
	message(STATUS "Using bundled zlib in '${ZLIB_SRC}'")
	set(ZLIB_INCLUDE "${ZLIB_SRC}")
	if(NOT WIN32)
		set(ZLIB_LIB "${ZLIB_SRC}/libz.a")
		ExternalProject_Add(zlib
			URL "http://download.draios.com/dependencies/zlib-1.2.11.tar.gz"
			URL_MD5 "1c9f62f0778697a09d36121ead88e08e"
			CONFIGURE_COMMAND "./configure"
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${ZLIB_LIB}
			INSTALL_COMMAND "")
	else()
		set(ZLIB_LIB "${ZLIB_SRC}/zdll.lib")
		ExternalProject_Add(zlib
			URL "http://download.draios.com/dependencies/zlib-1.2.11.tar.gz"
			URL_MD5 "1c9f62f0778697a09d36121ead88e08e"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND nmake -f win32/Makefile.msc
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${ZLIB_LIB}
			INSTALL_COMMAND "")
	endif()
endif()

#
# Intel tbb
#
if(NOT WIN32)
	option(USE_BUNDLED_TBB "Enable building of the bundled tbb" ${USE_BUNDLED_DEPS})
	if(NOT USE_BUNDLED_TBB)
		find_path(TBB_INCLUDE_DIR tbb.h PATH_SUFFIXES tbb)
		find_library(TBB_LIB NAMES tbb)
		if(TBB_INCLUDE_DIR AND TBB_LIB)
			message(STATUS "Found tbb: include: ${TBB_INCLUDE_DIR}, lib: ${TBB_LIB}")
		else()
			message(FATAL_ERROR "Couldn't find system tbb")
		endif()
	else()
		set(TBB_SRC "${PROJECT_BINARY_DIR}/tbb-prefix/src/tbb")

		message(STATUS "Using bundled tbb in '${TBB_SRC}'")

		set(TBB_INCLUDE_DIR "${TBB_SRC}/include/")
		set(TBB_LIB "${TBB_SRC}/build/lib_release/libtbb.a")
		ExternalProject_Add(tbb
			URL "http://s3.amazonaws.com/download.draios.com/dependencies/tbb-2018_U5.tar.gz"
			URL_MD5 "ff3ae09f8c23892fbc3008c39f78288f"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND ${CMD_MAKE} tbb_build_dir=${TBB_SRC}/build tbb_build_prefix=lib extra_inc=big_iron.inc
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${TBB_LIB}
			INSTALL_COMMAND "")
	endif()
endif()

#
# jq
#
if(NOT WIN32 AND NOT APPLE)
	option(USE_BUNDLED_JQ "Enable building of the bundled jq" ${USE_BUNDLED_DEPS})
	if(NOT USE_BUNDLED_JQ)
		find_path(JQ_INCLUDE jq.h PATH_SUFFIXES jq)
		find_library(JQ_LIB NAMES jq)
		if(JQ_INCLUDE AND JQ_LIB)
			message(STATUS "Found jq: include: ${JQ_INCLUDE}, lib: ${JQ_LIB}")
		else()
			message(FATAL_ERROR "Couldn't find system jq")
		endif()
	else()
		set(JQ_SRC "${PROJECT_BINARY_DIR}/jq-prefix/src/jq")
		message(STATUS "Using bundled jq in '${JQ_SRC}'")
		set(JQ_INCLUDE "${JQ_SRC}")
		set(JQ_LIB "${JQ_SRC}/.libs/libjq.a")
		ExternalProject_Add(jq
		URL "http://download.draios.com/dependencies/jq-1.5.tar.gz"
		URL_MD5 "0933532b086bd8b6a41c1b162b1731f9"
		CONFIGURE_COMMAND ./configure --disable-maintainer-mode --enable-all-static --disable-dependency-tracking
		BUILD_COMMAND ${CMD_MAKE} LDFLAGS=-all-static
		BUILD_IN_SOURCE 1
		BUILD_BYPRODUCTS ${JQ_LIB}
		PATCH_COMMAND wget -O jq-1.5-fix-tokenadd.patch https://github.com/stedolan/jq/commit/8eb1367ca44e772963e704a700ef72ae2e12babd.patch && patch -i jq-1.5-fix-tokenadd.patch
		INSTALL_COMMAND "")
	endif()
endif()

#
# ncurses, keep it simple for the moment
#
if(NOT WIN32)
	option(USE_BUNDLED_NCURSES "Enable building of the bundled ncurses" ${USE_BUNDLED_DEPS})

	if(NOT USE_BUNDLED_NCURSES)
		set(CURSES_NEED_NCURSES TRUE)
		find_package(Curses REQUIRED)
		message(STATUS "Found ncurses: include: ${CURSES_INCLUDE_DIR}, lib: ${CURSES_LIBRARIES}")
	else()
		set(CURSES_BUNDLE_DIR "${PROJECT_BINARY_DIR}/ncurses-prefix/src/ncurses")
		set(CURSES_INCLUDE_DIR "${CURSES_BUNDLE_DIR}/include/")
		set(CURSES_LIBRARIES "${CURSES_BUNDLE_DIR}/lib/libncurses.a")

		message(STATUS "Using bundled ncurses in '${CURSES_BUNDLE_DIR}'")

		ExternalProject_Add(ncurses
			URL "http://download.draios.com/dependencies/ncurses-6.0-20150725.tgz"
			URL_MD5 "32b8913312e738d707ae68da439ca1f4"
			CONFIGURE_COMMAND ./configure --without-cxx --without-cxx-binding --without-ada --without-manpages --without-progs --without-tests --with-terminfo-dirs=/etc/terminfo:/lib/terminfo:/usr/share/terminfo
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${CURSES_LIBRARIES}
			INSTALL_COMMAND "")
	endif()
endif()

if(NOT WIN32 AND NOT APPLE)
	#
	# libb64
	#
	option(USE_BUNDLED_B64 "Enable building of the bundled b64" ${USE_BUNDLED_DEPS})

	if(NOT USE_BUNDLED_B64)
		find_path(B64_INCLUDE NAMES b64/encode.h)
		find_library(B64_LIB NAMES b64)
		if(B64_INCLUDE AND B64_LIB)
			message(STATUS "Found b64: include: ${B64_INCLUDE}, lib: ${B64_LIB}")
		else()
			message(FATAL_ERROR "Couldn't find system b64")
		endif()
	else()
		set(B64_SRC "${PROJECT_BINARY_DIR}/b64-prefix/src/b64")
		message(STATUS "Using bundled b64 in '${B64_SRC}'")
		set(B64_INCLUDE "${B64_SRC}/include")
		set(B64_LIB "${B64_SRC}/src/libb64.a")
		ExternalProject_Add(b64
			URL "http://download.draios.com/dependencies/libb64-1.2.src.zip"
			URL_MD5 "a609809408327117e2c643bed91b76c5"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${B64_LIB}
			INSTALL_COMMAND "")
	endif()
endif()

if(NOT WIN32)
	#
	# OpenSSL
	#
	option(USE_BUNDLED_OPENSSL "Enable building of the bundled OpenSSL" ${USE_BUNDLED_DEPS})

	if(NOT USE_BUNDLED_OPENSSL)
		find_package(OpenSSL REQUIRED)
		message(STATUS "Found OpenSSL: include: ${OPENSSL_INCLUDE_DIR}, lib: ${OPENSSL_LIBRARIES}")
	else()
		set(OPENSSL_BUNDLE_DIR "${PROJECT_BINARY_DIR}/openssl-prefix/src/openssl")
		set(OPENSSL_INSTALL_DIR "${OPENSSL_BUNDLE_DIR}/target")
		set(OPENSSL_INCLUDE_DIR "${PROJECT_BINARY_DIR}/openssl-prefix/src/openssl/include")
		set(OPENSSL_LIBRARY_SSL "${OPENSSL_INSTALL_DIR}/lib/libssl.a")
		set(OPENSSL_LIBRARY_CRYPTO "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a")

		message(STATUS "Using bundled openssl in '${OPENSSL_BUNDLE_DIR}'")

		ExternalProject_Add(openssl
			URL "http://download.draios.com/dependencies/openssl-1.0.2n.tar.gz"
			URL_MD5 "13bdc1b1d1ff39b6fd42a255e74676a4"
			CONFIGURE_COMMAND ./config shared --prefix=${OPENSSL_INSTALL_DIR}
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${OPENSSL_LIBRARY_SSL} ${OPENSSL_LIBRARY_CRYPTO}
			INSTALL_COMMAND ${CMD_MAKE} install)
	endif()

	#
	# libcurl
	#
	option(USE_BUNDLED_CURL "Enable building of the bundled curl" ${USE_BUNDLED_DEPS})

	if(NOT USE_BUNDLED_CURL)
		find_package(CURL REQUIRED)
		message(STATUS "Found CURL: include: ${CURL_INCLUDE_DIR}, lib: ${CURL_LIBRARIES}")
	else()
		set(CURL_BUNDLE_DIR "${PROJECT_BINARY_DIR}/curl-prefix/src/curl")
		set(CURL_INCLUDE_DIR "${CURL_BUNDLE_DIR}/include/")
		set(CURL_LIBRARIES "${CURL_BUNDLE_DIR}/lib/.libs/libcurl.a")

		if(NOT USE_BUNDLED_OPENSSL)
			set(CURL_SSL_OPTION "--with-ssl")
		else()
			set(CURL_SSL_OPTION "--with-ssl=${OPENSSL_INSTALL_DIR}")
			message(STATUS "Using bundled curl in '${CURL_BUNDLE_DIR}'")
			message(STATUS "Using SSL for curl in '${CURL_SSL_OPTION}'")
		endif()


		ExternalProject_Add(curl
			DEPENDS openssl
			URL "http://download.draios.com/dependencies/curl-7.61.0.tar.bz2"
			URL_MD5 "31d0a9f48dc796a7db351898a1e5058a"
			CONFIGURE_COMMAND ./configure ${CURL_SSL_OPTION} --disable-threaded-resolver --disable-shared --enable-optimize --disable-curldebug --disable-rt --enable-http --disable-ftp --disable-file --disable-ldap --disable-ldaps --disable-rtsp --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp --disable-gopher --disable-sspi --disable-ntlm-wb --disable-tls-srp --without-winssl --without-darwinssl --without-polarssl --without-cyassl --without-nss --without-axtls --without-ca-path --without-ca-bundle --without-libmetalink --without-librtmp --without-winidn --without-libidn --without-libidn2 --without-nghttp2 --without-libssh2  --without-libpsl
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${CURL_LIBRARIES}
			INSTALL_COMMAND "")
	endif()
endif() # NOT WIN32 AND NOT APPLE

if(NOT WIN32 AND NOT APPLE)
	option(USE_BUNDLED_CARES "Enable building of the bundled c-ares" ${USE_BUNDLED_DEPS})
	if(NOT USE_BUNDLED_CARES)
		find_path(CARES_INCLUDE NAMES cares/ares.h ares.h)
		find_library(CARES_LIB NAMES cares)
		if(CARES_INCLUDE AND CARES_LIB)
			message(STATUS "Found c-ares: include: ${CARES_INCLUDE}, lib: ${CARES_LIB}")
		else()
			message(FATAL_ERROR "Couldn't find system c-ares")
		endif()
	else()
		set(CARES_SRC "${PROJECT_BINARY_DIR}/c-ares-prefix/src/c-ares")
		message(STATUS "Using bundled c-ares in '${CARES_SRC}'")
		set(CARES_INCLUDE "${CARES_SRC}/target/include")
		set(CARES_LIB "${CARES_SRC}/target/lib/libcares.a")
		ExternalProject_Add(c-ares
		URL "http://download.sysdig.com/dependencies/c-ares-1.13.0.tar.gz"
		URL_MD5 "d2e010b43537794d8bedfb562ae6bba2"
		CONFIGURE_COMMAND ./configure --prefix=${CARES_SRC}/target
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		BUILD_BYPRODUCTS ${CARES_INCLUDE} ${CARES_LIB}
		INSTALL_COMMAND ${CMD_MAKE} install)
	endif()

	option(USE_BUNDLED_PROTOBUF "Enable building of the bundled protobuf" ${USE_BUNDLED_DEPS})
	if(NOT USE_BUNDLED_PROTOBUF)
		find_program(PROTOC NAMES protoc)
		find_path(PROTOBUF_INCLUDE NAMES google/protobuf/message.h)
		find_library(PROTOBUF_LIB NAMES protobuf)
		if(PROTOC AND PROTOBUF_INCLUDE AND PROTOBUF_LIB)
			message(STATUS "Found protobuf: compiler: ${PROTOC}, include: ${PROTOBUF_INCLUDE}, lib: ${PROTOBUF_LIB}")
		else()
			message(FATAL_ERROR "Couldn't find system protobuf")
		endif()
	else()
		set(PROTOBUF_SRC "${PROJECT_BINARY_DIR}/protobuf-prefix/src/protobuf")
		message(STATUS "Using bundled protobuf in '${PROTOBUF_SRC}'")
		set(PROTOC "${PROTOBUF_SRC}/target/bin/protoc")
		set(PROTOBUF_INCLUDE "${PROTOBUF_SRC}/target/include")
		set(PROTOBUF_LIB "${PROTOBUF_SRC}/target/lib/libprotobuf.a")
		if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "s390x")
                        ExternalProject_Add(protobuf
                        DEPENDS openssl zlib
                        URL "http://download.sysdig.com/dependencies/protobuf-cpp-3.5.0.tar.gz"
                        URL_MD5 "e4ba8284a407712168593e79e6555eb2"
                        PATCH_COMMAND wget http://download.sysdig.com/dependencies/protobuf-3.5.0-s390x.patch && patch -p1 -i protobuf-3.5.0-s390x.patch
                        # TODO what if using system zlib?
                        CONFIGURE_COMMAND /usr/bin/env CPPFLAGS=-I${ZLIB_INCLUDE} LDFLAGS=-L${ZLIB_SRC} ./configure --with-zlib --prefix=${PROTOBUF_SRC}/target
                        COMMAND aclocal && automake
                        BUILD_COMMAND ${CMD_MAKE}
                        BUILD_IN_SOURCE 1
                        BUILD_BYPRODUCTS ${PROTOC} ${PROTOBUF_INCLUDE} ${PROTOBUF_LIB}
                        INSTALL_COMMAND make install)
                else()
                        ExternalProject_Add(protobuf
                        DEPENDS openssl zlib
                        URL "http://download.sysdig.com/dependencies/protobuf-cpp-3.5.0.tar.gz"
                        URL_MD5 "e4ba8284a407712168593e79e6555eb2"
                        # TODO what if using system zlib?
                        CONFIGURE_COMMAND /usr/bin/env CPPFLAGS=-I${ZLIB_INCLUDE} LDFLAGS=-L${ZLIB_SRC} ./configure --with-zlib --prefix=${PROTOBUF_SRC}/target
                        BUILD_COMMAND ${CMD_MAKE}
                        BUILD_IN_SOURCE 1
                        BUILD_BYPRODUCTS ${PROTOC} ${PROTOBUF_INCLUDE} ${PROTOBUF_LIB}
                        INSTALL_COMMAND make install)
                endif()
	endif()

	option(USE_BUNDLED_GRPC "Enable building of the bundled grpc" ${USE_BUNDLED_DEPS})
	if(NOT USE_BUNDLED_GRPC)
		find_path(GRPCXX_INCLUDE NAMES grpc++/grpc++.h)
		if(GRPCXX_INCLUDE)
			set(GRPC_INCLUDE ${GRPCXX_INCLUDE})
		else()
			find_path(GRPCPP_INCLUDE NAMES grpcpp/grpcpp.h)
			set(GRPC_INCLUDE ${GRPCPP_INCLUDE})
			add_definitions(-DGRPC_INCLUDE_IS_GRPCPP=1)
		endif()
		find_library(GRPC_LIB NAMES grpc_unsecure)
		find_library(GRPCPP_LIB NAMES grpc++_unsecure)
		if(GRPC_INCLUDE AND GRPC_LIB AND GRPCPP_LIB)
			message(STATUS "Found grpc: include: ${GRPC_INCLUDE}, C lib: ${GRPC_LIB}, C++ lib: ${GRPCPP_LIB}")
		else()
			message(FATAL_ERROR "Couldn't find system grpc")
		endif()
		find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin)
		if(NOT GRPC_CPP_PLUGIN)
			message(FATAL_ERROR "System grpc_cpp_plugin not found")
		endif()
	else()
		find_package(PkgConfig)
		if(NOT PKG_CONFIG_FOUND)
			message(FATAL_ERROR "pkg-config binary not found")
		endif()
		message(STATUS "Found pkg-config executable: ${PKG_CONFIG_EXECUTABLE}")
		set(GRPC_SRC "${PROJECT_BINARY_DIR}/grpc-prefix/src/grpc")
		message(STATUS "Using bundled grpc in '${GRPC_SRC}'")
		set(GRPC_INCLUDE "${GRPC_SRC}/include")
		set(GRPC_LIB "${GRPC_SRC}/libs/opt/libgrpc_unsecure.a")
		set(GRPCPP_LIB "${GRPC_SRC}/libs/opt/libgrpc++_unsecure.a")
		set(GRPC_CPP_PLUGIN "${GRPC_SRC}/bins/opt/grpc_cpp_plugin")

		get_filename_component(PROTOC_DIR ${PROTOC} PATH)

		ExternalProject_Add(grpc
		DEPENDS protobuf zlib c-ares
		URL "http://download.draios.com/dependencies/grpc-1.8.1.tar.gz"
		URL_MD5 "2fc42c182a0ed1b48ad77397f76bb3bc"
		CONFIGURE_COMMAND ""
		# TODO what if using system openssl, protobuf or cares?
		BUILD_COMMAND CFLAGS=-Wno-implicit-fallthrough HAS_SYSTEM_ZLIB=false LDFLAGS=-static PATH=${PROTOC_DIR}:$ENV{PATH} PKG_CONFIG_PATH=${OPENSSL_BUNDLE_DIR}:${PROTOBUF_SRC}:${CARES_SRC} PKG_CONFIG=${PKG_CONFIG_EXECUTABLE} make grpc_cpp_plugin static_cxx static_c
		BUILD_IN_SOURCE 1
		BUILD_BYPRODUCTS ${GRPC_LIB} ${GRPCPP_LIB}
		# TODO s390x support
		# TODO what if using system zlib
		PATCH_COMMAND rm -rf third_party/zlib && ln -s ${ZLIB_SRC} third_party/zlib && wget https://download.sysdig.com/dependencies/grpc-1.8.1-Makefile.patch && patch < grpc-1.8.1-Makefile.patch
		INSTALL_COMMAND "")
	endif()
endif() # NOT WIN32 AND NOT APPLE

option(CREATE_TEST_TARGETS "Enable make-targets for unit testing" ON)
if(CREATE_TEST_TARGETS AND NOT WIN32)
	option(USE_BUNDLED_GTEST "Enable building of the bundled gtest" ${USE_BUNDLED_DEPS})
	if(NOT USE_BUNDLED_GTEST)
		find_path(GTEST_INCLUDE_DIR PATH_SUFFIXES gtest NAMES gtest.h)
		find_library(GTEST_LIB NAMES gtest)
		find_library(GTEST_MAIN_LIB NAMES gtest_main)
		if(GTEST_INCLUDE_DIR AND GTEST_LIB AND GTEST_MAIN_LIB)
			message(STATUS "Found gtest: include: ${GTEST_INCLUDE_DIR}, lib: ${GTEST_LIB}, main lib: ${GTEST_MAIN_LIB}")
		else()
			message(FATAL_ERROR "Couldn't find system gtest")
		endif()
	else()
		# https://github.com/google/googletest/tree/master/googletest#incorporating-into-an-existing-cmake-project
		# Download and unpack googletest at configure time
		configure_file(CMakeListsGtestInclude.cmake googletest-download/CMakeLists.txt)
		execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
			RESULT_VARIABLE result
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
		if(result)
			message(FATAL_ERROR "CMake step for googletest failed: ${result}")
		endif()
		execute_process(COMMAND ${CMAKE_COMMAND} --build .
			RESULT_VARIABLE result
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
		if(result)
			message(FATAL_ERROR "Build step for googletest failed: ${result}")
		endif()

		# Add googletest directly to our build. This defines
		# the gtest and gtest_main targets.
		add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
		                 ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
		                 EXCLUDE_FROM_ALL)

		set(GTEST_INCLUDE_DIR "${gtest_SOURCE_DIR}/include/gtest")
		set(GTEST_MAIN_LIB "gtest_main")
	endif()
endif() # NOT WIN32

add_subdirectory(userspace/sysdig)
add_subdirectory(userspace/libscap)
add_subdirectory(userspace/libsinsp)

if(CREATE_TEST_TARGETS AND NOT WIN32)
		# Add unit test directories
		add_subdirectory(userspace/libsinsp/test)

		# Add command to run all unit tests at once via the make system.
		# This is preferred vs using ctest's add_test because it will build
		# the code and output to stdout.
		add_custom_target(run-unit-tests
			COMMAND ${CMAKE_MAKE_PROGRAM} run-unit-test-libsinsp
		)
endif()

set(CPACK_PACKAGE_NAME "${PACKAGE_NAME}")
set(CPACK_PACKAGE_VENDOR "Sysdig Inc.")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "sysdig, a system-level exploration and troubleshooting tool")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/scripts/description.txt")
set(CPACK_PACKAGE_VERSION "${SYSDIG_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PROJECT_CONFIG_FILE "${PROJECT_SOURCE_DIR}/CMakeCPackOptions.cmake")
set(CPACK_STRIP_FILES "ON")

set(CPACK_GENERATOR DEB RPM TGZ)

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Sysdig <support@sysdig.com>")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "http://www.sysdig.com")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "dkms (>= 2.1.0.0)")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_BINARY_DIR}/scripts/debian/postinst;${CMAKE_BINARY_DIR}/scripts/debian/prerm")

set(CPACK_RPM_PACKAGE_LICENSE "Apache v2.0")
set(CPACK_RPM_PACKAGE_URL "http://www.sysdig.com")
set(CPACK_RPM_PACKAGE_REQUIRES "dkms, gcc, make, kernel-devel, perl")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION /usr/src /usr/share/man /usr/share/man/man8)

include(CPack)
