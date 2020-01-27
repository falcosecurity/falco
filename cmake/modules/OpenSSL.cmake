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
    URL_MD5 "13bdc1b1d1ff39b6fd42a255e74676a4"
    # END CHANGE for CVE-2017-3735, CVE-2017-3731, CVE-2017-3737, CVE-2017-3738, CVE-2017-3736
    CONFIGURE_COMMAND ./config shared --prefix=${OPENSSL_INSTALL_DIR}
    BUILD_COMMAND ${CMD_MAKE}
    BUILD_IN_SOURCE 1
    INSTALL_COMMAND ${CMD_MAKE} install)
endif()
