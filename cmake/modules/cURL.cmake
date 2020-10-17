#
# Copyright (C) 2020 The Falco Authors.
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

if(NOT USE_BUNDLED_DEPS)
  find_package(CURL REQUIRED)
  message(STATUS "Found CURL: include: ${CURL_INCLUDE_DIR}, lib: ${CURL_LIBRARIES}")
else()
  set(CURL_BUNDLE_DIR "${PROJECT_BINARY_DIR}/curl-prefix/src/curl")
  set(CURL_INCLUDE_DIR "${CURL_BUNDLE_DIR}/include/")
  set(CURL_LIBRARIES "${CURL_BUNDLE_DIR}/lib/.libs/libcurl.a")

  set(CURL_SSL_OPTION "--with-ssl=${OPENSSL_INSTALL_DIR}")
  message(STATUS "Using bundled curl in '${CURL_BUNDLE_DIR}'")
  message(STATUS "Using SSL for curl in '${CURL_SSL_OPTION}'")

  externalproject_add(
    curl
    DEPENDS openssl
    # START CHANGE for CVE-2017-8816, CVE-2017-8817, CVE-2017-8818, CVE-2018-1000007
    URL "https://github.com/curl/curl/releases/download/curl-7_61_0/curl-7.61.0.tar.bz2"
    URL_HASH "SHA256=5f6f336921cf5b84de56afbd08dfb70adeef2303751ffb3e570c936c6d656c9c"
    # END CHANGE for CVE-2017-8816, CVE-2017-8817, CVE-2017-8818, CVE-2018-1000007
    CONFIGURE_COMMAND
      ./configure
      ${CURL_SSL_OPTION}
      --disable-shared
      --enable-optimize
      --disable-curldebug
      --disable-rt
      --enable-http
      --disable-ftp
      --disable-file
      --disable-ldap
      --disable-ldaps
      --disable-rtsp
      --disable-telnet
      --disable-tftp
      --disable-pop3
      --disable-imap
      --disable-smb
      --disable-smtp
      --disable-gopher
      --disable-sspi
      --disable-ntlm-wb
      --disable-tls-srp
      --without-winssl
      --without-darwinssl
      --without-polarssl
      --without-cyassl
      --without-nss
      --without-axtls
      --without-ca-path
      --without-ca-bundle
      --without-libmetalink
      --without-librtmp
      --without-winidn
      --without-libidn2
      --without-libpsl
      --without-nghttp2
      --without-libssh2
      --disable-threaded-resolver
      --without-brotli
    BUILD_COMMAND ${CMD_MAKE}
    BUILD_IN_SOURCE 1
    INSTALL_COMMAND "")
endif()
