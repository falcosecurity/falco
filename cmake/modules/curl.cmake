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

option(USE_BUNDLED_CURL "Enable building of the bundled curl" ${USE_BUNDLED_DEPS})

include(openssl)
include(zlib)

if(CURL_INCLUDE_DIRS)
	# we already have curl
elseif(NOT USE_BUNDLED_CURL)
	find_package(CURL REQUIRED)
	message(STATUS "Found CURL: include: ${CURL_INCLUDE_DIRS}, lib: ${CURL_LIBRARIES}")
else()
	if(BUILD_SHARED_LIBS)
		set(CURL_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
		set(CURL_STATIC_OPTION)
	else()
		set(CURL_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
		set(CURL_STATIC_OPTION --disable-shared)
	endif()
	set(CURL_BUNDLE_DIR "${PROJECT_BINARY_DIR}/curl-prefix/src/curl")
	set(CURL_INCLUDE_DIRS "${CURL_BUNDLE_DIR}/include/")
	set(CURL_LIBRARIES "${CURL_BUNDLE_DIR}/lib/.libs/libcurl${CURL_LIB_SUFFIX}")

	if(NOT USE_BUNDLED_OPENSSL)
		set(CURL_SSL_OPTION "--with-ssl")
	else()
		set(CURL_SSL_OPTION "--with-ssl=${OPENSSL_INSTALL_DIR}")
		message(STATUS "Using SSL for curl in '${OPENSSL_INSTALL_DIR}'")
	endif()

	if(NOT USE_BUNDLED_ZLIB)
		set(CURL_ZLIB_OPTION "--with-zlib")
	else()
		set(CURL_ZLIB_OPTION "--with-zlib=${ZLIB_SRC}")
		message(STATUS "Using zlib for curl in '${ZLIB_SRC}'")
	endif()
	message(STATUS "Using bundled curl in '${CURL_BUNDLE_DIR}'")

	if(NOT ENABLE_PIC)
		set(CURL_PIC_OPTION)
	else()
		set(CURL_PIC_OPTION "--with-pic")
	endif()

	if(NOT TARGET curl)
		ExternalProject_Add(
			curl
			PREFIX "${PROJECT_BINARY_DIR}/curl-prefix"
			DEPENDS openssl zlib
			URL "https://github.com/curl/curl/releases/download/curl-8_7_1/curl-8.7.1.tar.bz2"
			URL_HASH "SHA256=05bbd2b698e9cfbab477c33aa5e99b4975501835a41b7ca6ca71de03d8849e76"
			CONFIGURE_COMMAND
				./configure ${CURL_SSL_OPTION} ${CURL_ZLIB_OPTION} ${CURL_STATIC_OPTION}
				${CURL_PIC_OPTION} --enable-optimize --disable-curldebug --disable-rt --enable-http
				--disable-ftp --disable-file --disable-ldap --disable-ldaps --disable-rtsp
				--disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb
				--disable-smtp --disable-gopher --disable-sspi --disable-ntlm-wb --disable-tls-srp
				--without-winssl --without-polarssl --without-cyassl --without-nss --without-axtls
				--without-librtmp --without-winidn --without-libidn2 --without-libpsl
				--without-nghttp2 --without-libssh2 --with-ca-path=/etc/ssl/certs/
				--disable-threaded-resolver --without-brotli --without-zstd
			BUILD_COMMAND make
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${CURL_LIBRARIES}
			INSTALL_COMMAND ""
		)
		install(
			FILES "${CURL_LIBRARIES}"
			DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps"
		)
		install(
			DIRECTORY "${CURL_INCLUDE_DIRS}curl"
			DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps"
			FILES_MATCHING
			PATTERN "*.h"
		)
	endif()
endif()

if(NOT TARGET curl)
	add_custom_target(curl)
endif()

include_directories("${CURL_INCLUDE_DIRS}")
