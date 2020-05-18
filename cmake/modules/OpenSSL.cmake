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
  find_package(OpenSSL REQUIRED)
  message(STATUS "Found openssl: include: ${OPENSSL_INCLUDE_DIR}, lib: ${OPENSSL_LIBRARIES}")
  find_program(OPENSSL_BINARY openssl)
  if(NOT OPENSSL_BINARY)
    message(FATAL_ERROR "Couldn't find the openssl command line in PATH")
  else()
    message(STATUS "Found openssl: binary: ${OPENSSL_BINARY}")
  endif()
else()
  set(OPENSSL_BUNDLE_DIR "${PROJECT_BINARY_DIR}/openssl-prefix/src/openssl")
  set(OPENSSL_INSTALL_DIR "${OPENSSL_BUNDLE_DIR}/target")
  set(OPENSSL_INCLUDE_DIR "${PROJECT_BINARY_DIR}/openssl-prefix/src/openssl/include")
  set(OPENSSL_LIBRARY_SSL "${OPENSSL_INSTALL_DIR}/lib/libssl.a")
  set(OPENSSL_LIBRARY_CRYPTO "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a")
  set(OPENSSL_BINARY "${OPENSSL_INSTALL_DIR}/bin/openssl")

  message(STATUS "Using bundled openssl in '${OPENSSL_BUNDLE_DIR}'")

  ExternalProject_Add(
    openssl
    # START CHANGE for CVE-2017-3735, CVE-2017-3731, CVE-2017-3737, CVE-2017-3738, CVE-2017-3736
    URL "https://s3.amazonaws.com/download.draios.com/dependencies/openssl-1.0.2n.tar.gz"
    URL_HASH "SHA256=370babb75f278c39e0c50e8c4e7493bc0f18db6867478341a832a982fd15a8fe"
    # END CHANGE for CVE-2017-3735, CVE-2017-3731, CVE-2017-3737, CVE-2017-3738, CVE-2017-3736
    CONFIGURE_COMMAND ./config shared --prefix=${OPENSSL_INSTALL_DIR}
    BUILD_COMMAND ${CMD_MAKE}
    BUILD_IN_SOURCE 1
    INSTALL_COMMAND ${CMD_MAKE} install)
endif()
