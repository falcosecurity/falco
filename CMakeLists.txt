#
# Copyright (C) 2016-2018 Draios Inc dba Sysdig.
#
# This file is part of falco .
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
cmake_minimum_required(VERSION 3.3.2)

project(falco)

if(NOT SYSDIG_DIR)
  get_filename_component(SYSDIG_DIR "${PROJECT_SOURCE_DIR}/../sysdig" REALPATH)
endif()

# Custom CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")
list(APPEND CMAKE_MODULE_PATH "${SYSDIG_DIR}/cmake/modules")

option(BUILD_WARNINGS_AS_ERRORS "Enable building with -Wextra -Werror flags")

if(NOT DEFINED FALCO_ETC_DIR)
	set(FALCO_ETC_DIR "/etc/falco")
endif()

if(NOT DRAIOS_DEBUG_FLAGS)
	set(DRAIOS_DEBUG_FLAGS "-D_DEBUG")
endif()

string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE)
if (CMAKE_BUILD_TYPE STREQUAL "debug")
	set(KBUILD_FLAGS "${DRAIOS_DEBUG_FLAGS} ${DRAIOS_FEATURE_FLAGS}")
else()
	set(CMAKE_BUILD_TYPE "release")
	set(KBUILD_FLAGS "${DRAIOS_FEATURE_FLAGS}")
endif()

set(CMAKE_COMMON_FLAGS "-Wall -ggdb ${DRAIOS_FEATURE_FLAGS}")

if(BUILD_WARNINGS_AS_ERRORS)
	set(CMAKE_SUPPRESSED_WARNINGS "-Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set-variable -Wno-missing-field-initializers -Wno-sign-compare -Wno-type-limits -Wno-implicit-fallthrough -Wno-format-truncation")
	set(CMAKE_COMMON_FLAGS "${CMAKE_COMMON_FLAGS} -Wextra -Werror ${CMAKE_SUPPRESSED_WARNINGS}")
endif()

set(CMAKE_C_FLAGS "${CMAKE_COMMON_FLAGS}")
set(CMAKE_CXX_FLAGS "--std=c++0x ${CMAKE_COMMON_FLAGS}")

set(CMAKE_C_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")

set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")
add_definitions(-DK8S_DISABLE_THREAD)
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	add_definitions(-DHAS_CAPTURE)
endif()

# Create the falco version variable according to git index
if(NOT FALCO_VERSION)
  include(GetGitRevisionDescription)
  git_get_exact_tag(FALCO_TAG)
  if(NOT FALCO_TAG)
    git_describe(FALCO_VERSION "--always")
    git_local_changes(FALCO_CHANGES)
    if(FALCO_CHANGES STREQUAL "DIRTY")
      string(TOLOWER "${FALCO_CHANGES}" FALCO_CHANGES)
      set(FALCO_VERSION "${FALCO_VERSION}.${FALCO_CHANGES}")
    endif()
    set(FALCO_VERSION "0.${FALCO_VERSION}")
  else()
    set(FALCO_VERSION "${FALCO_TAG}")
    string(REGEX
           REPLACE "^v([0-9]+)(\\.[0-9]+)(\\.[0-9]+)?"
                   "\\1\\2\\3"
                   FALCO_VERSION
                   ${FALCO_VERSION})
  endif()
endif()
message(STATUS "Falco version: ${FALCO_VERSION}")

set(PACKAGE_NAME "falco")
set(PROBE_VERSION "${FALCO_VERSION}")
set(PROBE_NAME "falco-probe")
set(PROBE_DEVICE_NAME "falco")
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX /usr CACHE PATH "Default install path" FORCE)
endif()

set(CMD_MAKE make)

# make luaJIT work on OS X
if(APPLE)
	set(CMAKE_EXE_LINKER_FLAGS "-pagezero_size 10000 -image_base 100000000")
endif()

include(ExternalProject)

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

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
        set(ZLIB_LIB "${ZLIB_SRC}/libz.a")
        ExternalProject_Add(zlib
		# START CHANGE for CVE-2016-9840, CVE-2016-9841, CVE-2016-9842, CVE-2016-9843
		URL "https://s3.amazonaws.com/download.draios.com/dependencies/zlib-1.2.11.tar.gz"
                URL_MD5 "1c9f62f0778697a09d36121ead88e08e"
		# END CHANGE for CVE-2016-9840, CVE-2016-9841, CVE-2016-9842, CVE-2016-9843
		CONFIGURE_COMMAND "./configure"
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND "")
endif()

#
# jq
#
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
                URL "https://s3.amazonaws.com/download.draios.com/dependencies/jq-1.5.tar.gz"
                URL_MD5 "0933532b086bd8b6a41c1b162b1731f9"
                CONFIGURE_COMMAND ./configure --disable-maintainer-mode --enable-all-static --disable-dependency-tracking
                BUILD_COMMAND ${CMD_MAKE} LDFLAGS=-all-static
                BUILD_IN_SOURCE 1
		PATCH_COMMAND curl -L https://github.com/stedolan/jq/commit/8eb1367ca44e772963e704a700ef72ae2e12babd.patch | patch
                INSTALL_COMMAND "")
endif()

set(JSONCPP_SRC "${SYSDIG_DIR}/userspace/libsinsp/third-party/jsoncpp")
set(JSONCPP_INCLUDE "${JSONCPP_SRC}")
set(JSONCPP_LIB_SRC "${JSONCPP_SRC}/jsoncpp.cpp")

#
# nlohmann-json
#
option(USE_BUNDLED_NJSON "Enable building of the bundled nlohmann-json" ${USE_BUNDLED_DEPS})

if(NOT USE_BUNDLED_NJSON)
	find_path(NJSON_INCLUDE json.hpp PATH_SUFFIXES nlohmann)
	if(NJSON_INCLUDE)
		message(STATUS "Found nlohmann-json: include: ${NJSON_INCLUDE}")
	else()
		message(FATAL_ERROR "Couldn't find system nlohmann-json")
	endif()
else()
	# No distinction needed for windows. The implementation is
	# solely in json.hpp.
	set(NJSON_SRC "${PROJECT_BINARY_DIR}/njson-prefix/src/njson")
	message(STATUS "Using bundled nlohmann-json in '${NJSON_SRC}'")
	set(NJSON_INCLUDE "${NJSON_SRC}/single_include")
	ExternalProject_Add(njson
		URL "https://s3.amazonaws.com/download.draios.com/dependencies/njson-3.3.0.tar.gz"
		URL_MD5 "e26760e848656a5da400662e6c5d999a"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ""
		INSTALL_COMMAND "")
endif()

#
# curses
#
# we pull this in because libsinsp won't build without it

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
		URL "https://s3.amazonaws.com/download.draios.com/dependencies/ncurses-6.0-20150725.tgz"
		URL_MD5 "32b8913312e738d707ae68da439ca1f4"
		CONFIGURE_COMMAND ./configure --without-cxx --without-cxx-binding --without-ada --without-manpages --without-progs --without-tests --with-terminfo-dirs=/etc/terminfo:/lib/terminfo:/usr/share/terminfo
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND "")
endif()

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
		URL "https://s3.amazonaws.com/download.draios.com/dependencies/libb64-1.2.src.zip"
		URL_MD5 "a609809408327117e2c643bed91b76c5"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND "")
endif()

#
# yamlcpp
#
option(USE_BUNDLED_YAMLCPP "Enable building of the bundled yamlcpp" ${USE_BUNDLED_DEPS})

if(NOT USE_BUNDLED_YAMLCPP)
	find_path(YAMLCPP_INCLUDE_DIR NAMES yaml-cpp/yaml.h)
	find_library(YAMLCPP_LIB NAMES yaml-cpp)
	if(YAMLCPP_INCLUDE_DIR AND YAMLCPP_LIB)
		message(STATUS "Found yamlcpp: include: ${YAMLCPP_INCLUDE_DIR}, lib: ${YAMLCPP_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system yamlcpp")
	endif()
else()
	set(YAMLCPP_SRC "${PROJECT_BINARY_DIR}/yamlcpp-prefix/src/yamlcpp")
	message(STATUS "Using bundled yaml-cpp in '${YAMLCPP_SRC}'")
	set(YAMLCPP_LIB "${YAMLCPP_SRC}/libyaml-cpp.a")
	set(YAMLCPP_INCLUDE_DIR "${YAMLCPP_SRC}/include")
	ExternalProject_Add(yamlcpp
		URL "https://s3.amazonaws.com/download.draios.com/dependencies/yaml-cpp-yaml-cpp-0.6.2.tar.gz"
		URL_MD5 "5b943e9af0060d0811148b037449ef82"
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND "")
endif()

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
		# START CHANGE for CVE-2017-3735, CVE-2017-3731, CVE-2017-3737, CVE-2017-3738, CVE-2017-3736
		URL "https://s3.amazonaws.com/download.draios.com/dependencies/openssl-1.0.2n.tar.gz"
                URL_MD5 "13bdc1b1d1ff39b6fd42a255e74676a4"
		# END CHANGE for CVE-2017-3735, CVE-2017-3731, CVE-2017-3737, CVE-2017-3738, CVE-2017-3736
		CONFIGURE_COMMAND ./config shared --prefix=${OPENSSL_INSTALL_DIR}
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
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
		# START CHANGE for CVE-2017-8816, CVE-2017-8817, CVE-2017-8818, CVE-2018-1000007
		URL "https://s3.amazonaws.com/download.draios.com/dependencies/curl-7.61.0.tar.bz2"
		URL_MD5 "31d0a9f48dc796a7db351898a1e5058a"
		# END CHANGE for CVE-2017-8816, CVE-2017-8817, CVE-2017-8818, CVE-2018-1000007
		CONFIGURE_COMMAND ./configure ${CURL_SSL_OPTION} --disable-shared --enable-optimize --disable-curldebug --disable-rt --enable-http --disable-ftp --disable-file --disable-ldap --disable-ldaps --disable-rtsp --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp --disable-gopher --disable-sspi --disable-ntlm-wb --disable-tls-srp --without-winssl --without-darwinssl --without-polarssl --without-cyassl --without-nss --without-axtls --without-ca-path --without-ca-bundle --without-libmetalink --without-librtmp --without-winidn --without-libidn2 --without-libpsl --without-nghttp2 --without-libssh2 --disable-threaded-resolver --without-brotli
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND "")
endif()

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
	set(LUAJIT_LIB "${LUAJIT_SRC}/libluajit.a")
	ExternalProject_Add(luajit
		URL "https://s3.amazonaws.com/download.draios.com/dependencies/LuaJIT-2.0.3.tar.gz"
		URL_MD5 "f14e9104be513913810cd59c8c658dc0"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND "")
endif()

#
# Lpeg
#
option(USE_BUNDLED_LPEG "Enable building of the bundled lpeg" ${USE_BUNDLED_DEPS})

if(NOT USE_BUNDLED_LPEG)
	find_library(LPEG_LIB NAMES lpeg.a)
	if(LPEG_LIB)
		message(STATUS "Found lpeg: lib: ${LPEG_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system lpeg")
	endif()
else()
	set(LPEG_SRC "${PROJECT_BINARY_DIR}/lpeg-prefix/src/lpeg")
	set(LPEG_LIB "${PROJECT_BINARY_DIR}/lpeg-prefix/src/lpeg/build/lpeg.a")
	message(STATUS "Using bundled lpeg in '${LPEG_SRC}'")
	set(LPEG_DEPENDENCIES "")
	if(USE_BUNDLED_LUAJIT)
		list(APPEND LPEG_DEPENDENCIES "luajit")
	endif()
	ExternalProject_Add(lpeg
		DEPENDS ${LPEG_DEPENDENCIES}
		URL "https://s3.amazonaws.com/download.draios.com/dependencies/lpeg-1.0.0.tar.gz"
		URL_MD5 "0aec64ccd13996202ad0c099e2877ece"
		BUILD_COMMAND LUA_INCLUDE=${LUAJIT_INCLUDE} "${PROJECT_SOURCE_DIR}/scripts/build-lpeg.sh" "${LPEG_SRC}/build"
		BUILD_IN_SOURCE 1
		CONFIGURE_COMMAND ""
		INSTALL_COMMAND "")
endif()

#
# Libyaml
#
option(USE_BUNDLED_LIBYAML "Enable building of the bundled libyaml" ${USE_BUNDLED_DEPS})
if(NOT USE_BUNDLED_LIBYAML)
	# Note: to distinguish libyaml.a and yaml.a we specify a full
	# file name here, so you'll have to arrange for static
	# libraries being available.
	find_library(LIBYAML_LIB NAMES libyaml.a)
	if(LIBYAML_LIB)
		message(STATUS "Found libyaml: lib: ${LIBYAML_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system libyaml")
	endif()
else()
	find_path(AUTORECONF_BIN NAMES autoreconf)
	if(AUTORECONF_BIN)
		message(STATUS "Found autoreconf: ${AUTORECONF_BIN}")
	else()
		message(FATAL_ERROR "Couldn't find system autoreconf. Please install autoreconf before continuing or use system libyaml")
	endif()

	set(LIBYAML_SRC "${PROJECT_BINARY_DIR}/libyaml-prefix/src/libyaml/src")
	set(LIBYAML_INCLUDE "${PROJECT_BINARY_DIR}/libyaml-prefix/src/libyaml/include")
	set(LIBYAML_LIB "${LIBYAML_SRC}/.libs/libyaml.a")
	message(STATUS "Using bundled libyaml in '${LIBYAML_SRC}'")
	ExternalProject_Add(libyaml
		URL "https://s3.amazonaws.com/download.draios.com/dependencies/libyaml-0.1.4.tar.gz"
		URL_MD5 "4a4bced818da0b9ae7fc8ebc690792a7"
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		CONFIGURE_COMMAND ./bootstrap && ./configure
		INSTALL_COMMAND "")
endif()

#
# lyaml
#
option(USE_BUNDLED_LYAML "Enable building of the bundled lyaml" ${USE_BUNDLED_DEPS})
if(NOT USE_BUNDLED_LYAML)
	# Note: to distinguish libyaml.a and yaml.a we specify a full
	# file name here, so you'll have to arrange for static
	# libraries being available.
	find_library(LYAML_LIB NAMES yaml.a)
	if(LYAML_LIB)
		message(STATUS "Found lyaml: lib: ${LYAML_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system lyaml")
	endif()
else()
	set(LYAML_SRC "${PROJECT_BINARY_DIR}/lyaml-prefix/src/lyaml/ext/yaml")
	set(LYAML_LIB "${LYAML_SRC}/.libs/yaml.a")
	message(STATUS "Using bundled lyaml in '${LYAML_SRC}'")
	set(LYAML_DEPENDENCIES "")
	if(USE_BUNDLED_LUAJIT)
		list(APPEND LYAML_DEPENDENCIES "luajit")
	endif()
	if(USE_BUNDLED_LIBYAML)
		list(APPEND LYAML_DEPENDENCIES "libyaml")
	endif()

	ExternalProject_Add(lyaml
		DEPENDS ${LYAML_DEPENDENCIES}
		URL "https://s3.amazonaws.com/download.draios.com/dependencies/lyaml-release-v6.0.tar.gz"
		URL_MD5 "dc3494689a0dce7cf44e7a99c72b1f30"
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		CONFIGURE_COMMAND ./configure --enable-static LIBS=-L${LIBYAML_SRC}/.libs CFLAGS=-I${LIBYAML_INCLUDE} CPPFLAGS=-I${LIBYAML_INCLUDE} LUA_INCLUDE=-I${LUAJIT_INCLUDE} LUA=${LUAJIT_SRC}/luajit
		INSTALL_COMMAND sh -c "cp -R ${PROJECT_BINARY_DIR}/lyaml-prefix/src/lyaml/lib/* ${PROJECT_SOURCE_DIR}/userspace/engine/lua")
endif()

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
		URL "https://s3.amazonaws.com/download.draios.com/dependencies/tbb-2018_U5.tar.gz"
		URL_MD5 "ff3ae09f8c23892fbc3008c39f78288f"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ${CMD_MAKE} tbb_build_dir=${TBB_SRC}/build tbb_build_prefix=lib extra_inc=big_iron.inc
		BUILD_IN_SOURCE 1
		BUILD_BYPRODUCTS ${TBB_LIB}
		INSTALL_COMMAND "")
endif()

#
# civetweb
#
option(USE_BUNDLED_CIVETWEB "Enable building of the bundled civetweb" ${USE_BUNDLED_DEPS})

if(NOT USE_BUNDLED_CIVETWEB)
	find_library(CIVETWEB_LIB NAMES civetweb)
	if(CIVETWEB_LIB)
		message(STATUS "Found civetweb: lib: ${CIVETWEB_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system civetweb")
	endif()
else()
	set(CIVETWEB_SRC "${PROJECT_BINARY_DIR}/civetweb-prefix/src/civetweb/")
	set(CIVETWEB_LIB "${CIVETWEB_SRC}/install/lib/libcivetweb.a")
	set(CIVETWEB_INCLUDE_DIR "${CIVETWEB_SRC}/install/include")
	message(STATUS "Using bundled civetweb in '${CIVETWEB_SRC}'")
	set(CIVETWEB_DEPENDENCIES "")
	if(USE_BUNDLED_OPENSSL)
	 	list(APPEND CIVETWEB_DEPENDENCIES "openssl")
	endif()
	ExternalProject_Add(civetweb
		DEPENDS ${CIVETWEB_DEPENDENCIES}
		URL "https://s3.amazonaws.com/download.draios.com/dependencies/civetweb-1.11.tar.gz"
                URL_MD5 "b6d2175650a27924bccb747cbe084cd4"
		CONFIGURE_COMMAND ${CMAKE_COMMAND} -E make_directory ${CIVETWEB_SRC}/install/lib
		          COMMAND ${CMAKE_COMMAND} -E make_directory ${CIVETWEB_SRC}/install/include
                BUILD_IN_SOURCE 1
                BUILD_COMMAND ${CMD_MAKE} COPT="-DNO_FILES" WITH_CPP=1
		INSTALL_COMMAND ${CMD_MAKE} install-lib install-headers PREFIX=${CIVETWEB_SRC}/install WITH_CPP=1)
endif()

option(USE_BUNDLED_CARES "Enable building of the bundled c-ares" ${USE_BUNDLED_DEPS})
if(NOT USE_BUNDLED_CARES)
	find_path(CARES_INCLUDE NAMES cares/ares.h)
	find_library(CARES_LIB NAMES libcares.a)
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
		URL "https://download.sysdig.com/dependencies/c-ares-1.13.0.tar.gz"
		URL_MD5 "d2e010b43537794d8bedfb562ae6bba2"
		CONFIGURE_COMMAND ./configure --prefix=${CARES_SRC}/target
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		BUILD_BYPRODUCTS ${CARES_INCLUDE} ${CARES_LIB}
		INSTALL_COMMAND ${CMD_MAKE} install)
endif()

option(USE_BUNDLED_INJA "Enable building of the bundled inja" ${USE_BUNDLED_DEPS})
if(NOT USE_BUNDLED_INJA)
	find_path(INJA_INCLUDE inja.hpp PATH_SUFFIXES inja)
	if(INJA_INCLUDE)
		message(STATUS "Found inja: include: ${INJA_INCLUDE}")
	else()
		message(FATAL_ERROR "Couldn't find system inja")
	endif()
else()
	set(INJA_SRC "${PROJECT_BINARY_DIR}/inja-prefix/src/inja")
	message(STATUS "Using bundled inja in '${INJA_SRC}'")
	set(INJA_INCLUDE "${INJA_SRC}/single_include")
	ExternalProject_Add(inja
		URL "https://github.com/pantor/inja/archive/v2.1.0.tar.gz"
		URL_MD5 "eea698f12cb2ce48bcadda7629e5aa62"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ""
		INSTALL_COMMAND "")
endif()

option(USE_BUNDLED_PROTOBUF "Enable building of the bundled protobuf" ${USE_BUNDLED_DEPS})
if(NOT USE_BUNDLED_PROTOBUF)
	find_program(PROTOC NAMES protoc)
	find_path(PROTOBUF_INCLUDE NAMES google/protobuf/message.h)
	find_library(PROTOBUF_LIB NAMES libprotobuf.a)
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
	ExternalProject_Add(protobuf
		DEPENDS openssl zlib
		URL "https://github.com/google/protobuf/releases/download/v3.5.0/protobuf-cpp-3.5.0.tar.gz"
		URL_MD5 "e4ba8284a407712168593e79e6555eb2"
		# TODO what if using system zlib?
		CONFIGURE_COMMAND /usr/bin/env CPPFLAGS=-I${ZLIB_INCLUDE} LDFLAGS=-L${ZLIB_SRC} ./configure --with-zlib --prefix=${PROTOBUF_SRC}/target
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		BUILD_BYPRODUCTS ${PROTOC} ${PROTOBUF_INCLUDE} ${PROTOBUF_LIB}
		# TODO s390x support
		INSTALL_COMMAND make install)
endif()

option(USE_BUNDLED_GRPC "Enable building of the bundled grpc" ${USE_BUNDLED_DEPS})
if(NOT USE_BUNDLED_GRPC)
	find_path(GRPC_INCLUDE grpc++/impl/codegen/rpc_method.h)
	find_library(GRPC_LIB NAMES libgrpc_unsecure.a)
	find_library(GRPCPP_LIB NAMES libgrpc++_unsecure.a)
	if(GRPC_INCLUDE AND GRPC_LIB AND GRPCPP_LIB)
		message(STATUS "Found grpc: include: ${GRPC_INCLUDE}, C lib: ${GRPC_LIB}, C++ lib: ${GRPC_PP_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system grpc")
	endif()
	find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin)
	if(NOT GRPC_CPP_PLUGIN)
		message(FATAL_ERROR "System grpc_cpp_plugin not found")
	endif()
else()
	set(GRPC_SRC "${PROJECT_BINARY_DIR}/grpc-prefix/src/grpc")
	message(STATUS "Using bundled grpc in '${GRPC_SRC}'")
	set(GRPC_INCLUDE "${GRPC_SRC}/include")
	set(GRPC_LIB "${GRPC_SRC}/libs/opt/libgrpc_unsecure.a")
	set(GRPCPP_LIB "${GRPC_SRC}/libs/opt/libgrpc++_unsecure.a")
	set(GRPC_CPP_PLUGIN "${GRPC_SRC}/bins/opt/grpc_cpp_plugin")

	get_filename_component(PROTOC_DIR ${PROTOC} DIRECTORY)

	ExternalProject_Add(grpc
		DEPENDS protobuf zlib c-ares
		URL "https://s3.amazonaws.com/download.draios.com/dependencies/grpc-1.8.1.tar.gz"
		URL_MD5 "2fc42c182a0ed1b48ad77397f76bb3bc"
		CONFIGURE_COMMAND ""
		# TODO what if using system openssl, protobuf or cares?
		BUILD_COMMAND sh -c "CFLAGS=-Wno-implicit-fallthrough CXXFLAGS=\"-Wno-ignored-qualifiers -Wno-stringop-truncation\" HAS_SYSTEM_ZLIB=false LDFLAGS=-static PATH=${PROTOC_DIR}:$ENV{PATH} PKG_CONFIG_PATH=${OPENSSL_BUNDLE_DIR}:${PROTOBUF_SRC}:${CARES_SRC} make grpc_cpp_plugin static_cxx static_c"
		BUILD_IN_SOURCE 1
		BUILD_BYPRODUCTS ${GRPC_LIB} ${GRPCPP_LIB}
		# TODO s390x support
		# TODO what if using system zlib
		PATCH_COMMAND rm -rf third_party/zlib && ln -s ${ZLIB_SRC} third_party/zlib && curl -L https://download.sysdig.com/dependencies/grpc-1.1.4-Makefile.patch | patch
		INSTALL_COMMAND "")
endif()


install(FILES falco.yaml
	DESTINATION "${FALCO_ETC_DIR}")

add_subdirectory(test)
add_subdirectory(rules)
add_subdirectory(docker)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	add_subdirectory("${SYSDIG_DIR}/driver" "${PROJECT_BINARY_DIR}/driver")
	include(FindMakedev)
endif()
add_subdirectory("${SYSDIG_DIR}/userspace/libscap" "${PROJECT_BINARY_DIR}/userspace/libscap")
add_subdirectory("${SYSDIG_DIR}/userspace/libsinsp" "${PROJECT_BINARY_DIR}/userspace/libsinsp")

set(FALCO_SINSP_LIBRARY sinsp)
set(FALCO_SHARE_DIR share/falco)
set(FALCO_ABSOLUTE_SHARE_DIR "${CMAKE_INSTALL_PREFIX}/${FALCO_SHARE_DIR}")
set(FALCO_BIN_DIR bin)
add_subdirectory(scripts)
add_subdirectory(userspace/engine)
add_subdirectory(userspace/falco)
add_subdirectory(tests)

set(CPACK_PACKAGE_NAME "${PACKAGE_NAME}")
set(CPACK_PACKAGE_VENDOR "Sysdig Inc.")
set(CPACK_PACKAGE_CONTACT "opensource@sysdig.com")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Falco - Container Native Runtime Security")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/scripts/description.txt")
set(CPACK_PACKAGE_VERSION "${FALCO_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PROJECT_CONFIG_FILE "${PROJECT_SOURCE_DIR}/CMakeCPackOptions.cmake")
set(CPACK_STRIP_FILES "ON")
set(CPACK_PACKAGE_RELOCATABLE "OFF")

set(CPACK_GENERATOR DEB RPM TGZ)

set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://www.falco.org")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "dkms (>= 2.1.0.0)")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_BINARY_DIR}/scripts/debian/postinst;${CMAKE_BINARY_DIR}/scripts/debian/prerm;${PROJECT_SOURCE_DIR}/scripts/debian/postrm;${PROJECT_SOURCE_DIR}/cpack/debian/conffiles")

set(CPACK_RPM_PACKAGE_LICENSE "Apache v2.0")
set(CPACK_RPM_PACKAGE_URL "https://www.falco.org")
set(CPACK_RPM_PACKAGE_REQUIRES "dkms, gcc, make, kernel-devel, perl")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postuninstall")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION /usr/src /usr/share/man /usr/share/man/man8 /etc /usr /usr/bin /usr/share /etc/rc.d /etc/rc.d/init.d)
set(CPACK_RPM_PACKAGE_RELOCATABLE "OFF")

include(CPack)
