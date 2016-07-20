cmake_minimum_required(VERSION 2.8.2)

project(falco)

if(NOT DEFINED FALCO_VERSION)
	set(FALCO_VERSION "0.1.1dev")
endif()

if(NOT DEFINED FALCO_ETC_DIR)
	set(FALCO_ETC_DIR "/etc")
endif()

if(NOT CMAKE_BUILD_TYPE)
	SET(CMAKE_BUILD_TYPE Release)
endif()

set(DRAIOS_DEBUG_FLAGS "-D_DEBUG")

set(CMAKE_C_FLAGS "-Wall -ggdb ${DRAIOS_FEATURE_FLAGS}")
set(CMAKE_CXX_FLAGS "-Wall -ggdb --std=c++0x ${DRAIOS_FEATURE_FLAGS}")

set(CMAKE_C_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")

set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")
add_definitions(-DK8S_DISABLE_THREAD)
add_definitions(-DHAS_CAPTURE)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(KBUILD_FLAGS "${DRAIOS_DEBUG_FLAGS} ${DRAIOS_FEATURE_FLAGS}")
else()
	set(KBUILD_FLAGS "${DRAIOS_FEATURE_FLAGS}")
endif()

set(PACKAGE_NAME "falco")
set(PROBE_VERSION "${FALCO_VERSION}")
set(PROBE_NAME "sysdig-probe")
set(PROBE_DEVICE_NAME "sysdig")
set(CMAKE_INSTALL_PREFIX /usr)

set(CMD_MAKE make)

set(SYSDIG_DIR "${PROJECT_SOURCE_DIR}/../sysdig")

include(ExternalProject)

set(ZLIB_SRC "${PROJECT_BINARY_DIR}/zlib-prefix/src/zlib")
message(STATUS "Using bundled zlib in '${ZLIB_SRC}'")
set(ZLIB_INCLUDE "${ZLIB_SRC}")
set(ZLIB_LIB "${ZLIB_SRC}/libz.a")
ExternalProject_Add(zlib
		URL "http://download.draios.com/dependencies/zlib-1.2.8.tar.gz"
		URL_MD5 "44d667c142d7cda120332623eab69f40"
		CONFIGURE_COMMAND "./configure"
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND "")

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
                INSTALL_COMMAND "")

set(JSONCPP_SRC "${SYSDIG_DIR}/userspace/libsinsp/third-party/jsoncpp")
set(JSONCPP_INCLUDE "${JSONCPP_SRC}")
set(JSONCPP_LIB_SRC "${JSONCPP_SRC}/jsoncpp.cpp")

# we pull this in because libsinsp won't build without it
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
		INSTALL_COMMAND "")


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
		INSTALL_COMMAND "")


set(YAMLCPP_SRC "${PROJECT_BINARY_DIR}/yamlcpp-prefix/src/yamlcpp")
message(STATUS "Using bundled yaml-cpp in '${YAMLCPP_SRC}'")
set(YAMLCPP_LIB "${YAMLCPP_SRC}/libyaml-cpp.a")
set(YAMLCPP_INCLUDE_DIR "${YAMLCPP_SRC}/include")
# Once the next version of yaml-cpp is released (first version not requiring
# boost), we can switch to that and no longer pull from github.
ExternalProject_Add(yamlcpp
		GIT_REPOSITORY "https://github.com/jbeder/yaml-cpp.git"
		GIT_TAG "7d2873ce9f2202ea21b6a8c5ecbc9fe38032c229"
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND "")

set(OPENSSL_BUNDLE_DIR "${PROJECT_BINARY_DIR}/openssl-prefix/src/openssl")
set(OPENSSL_INSTALL_DIR "${OPENSSL_BUNDLE_DIR}/target")
set(OPENSSL_INCLUDE_DIR "${PROJECT_BINARY_DIR}/openssl-prefix/src/openssl/include")
set(OPENSSL_LIBRARY_SSL "${OPENSSL_INSTALL_DIR}/lib/libssl.a")
set(OPENSSL_LIBRARY_CRYPTO "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a")

message(STATUS "Using bundled openssl in '${OPENSSL_BUNDLE_DIR}'")

ExternalProject_Add(openssl
		URL "http://download.draios.com/dependencies/openssl-1.0.2d.tar.gz"
		URL_MD5 "38dd619b2e77cbac69b99f52a053d25a"
		CONFIGURE_COMMAND ./config shared --prefix=${OPENSSL_INSTALL_DIR}
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND ${CMD_MAKE} install)

set(CURL_SSL_OPTION "--with-ssl=${OPENSSL_INSTALL_DIR}")


set(CURL_BUNDLE_DIR "${PROJECT_BINARY_DIR}/curl-prefix/src/curl")
set(CURL_INCLUDE_DIR "${CURL_BUNDLE_DIR}/include/")
set(CURL_LIBRARIES "${CURL_BUNDLE_DIR}/lib/.libs/libcurl.a")
message(STATUS "Using bundled curl in '${CURL_BUNDLE_DIR}'")
message(STATUS "Using SSL for curl in '${CURL_SSL_OPTION}'")

ExternalProject_Add(curl
		DEPENDS openssl
		URL "http://download.draios.com/dependencies/curl-7.45.0.tar.bz2"
		URL_MD5 "62c1a352b28558f25ba6209214beadc8"
		CONFIGURE_COMMAND ./configure ${CURL_SSL_OPTION} --disable-shared --enable-optimize --disable-curldebug --disable-rt --enable-http --disable-ftp --disable-file --disable-ldap --disable-ldaps --disable-rtsp --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp --disable-gopher --disable-sspi --disable-ntlm-wb --disable-tls-srp --without-winssl --without-darwinssl --without-polarssl --without-cyassl --without-nss --without-axtls --without-ca-path --without-ca-bundle --without-libmetalink --without-librtmp --without-winidn --without-libidn --without-nghttp2 --without-libssh2
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND "")

set(LUAJIT_SRC "${PROJECT_BINARY_DIR}/luajit-prefix/src/luajit/src")
message(STATUS "Using bundled LuaJIT in '${LUAJIT_SRC}'")
set(LUAJIT_INCLUDE "${LUAJIT_SRC}")
set(LUAJIT_LIB "${LUAJIT_SRC}/libluajit.a")
ExternalProject_Add(luajit
		URL "http://download.draios.com/dependencies/LuaJIT-2.0.3.tar.gz"
		URL_MD5 "f14e9104be513913810cd59c8c658dc0"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND "")

set (LPEG_SRC "${PROJECT_BINARY_DIR}/lpeg-prefix/src/lpeg")
set (LPEG_LIB "${PROJECT_BINARY_DIR}/lpeg-prefix/src/lpeg/build/lpeg.a")
ExternalProject_Add(lpeg
                    DEPENDS luajit
		    URL "http://s3.amazonaws.com/download.draios.com/dependencies/lpeg-1.0.0.tar.gz"
                    URL_MD5 "0aec64ccd13996202ad0c099e2877ece"
                    BUILD_COMMAND LUA_INCLUDE=${LUAJIT_INCLUDE} "${PROJECT_SOURCE_DIR}/scripts/build-lpeg.sh" "${LPEG_SRC}/build"
                    BUILD_IN_SOURCE 1
		    CONFIGURE_COMMAND ""
                    INSTALL_COMMAND "")


set (LIBYAML_SRC "${PROJECT_BINARY_DIR}/libyaml-prefix/src/libyaml/src")
set(LIBYAML_LIB "${LIBYAML_SRC}/.libs/libyaml.a")
ExternalProject_Add(libyaml
		    URL "http://download.draios.com/dependencies/libyaml-0.1.4.tar.gz"
                    URL_MD5 "4a4bced818da0b9ae7fc8ebc690792a7"
                    BUILD_COMMAND ${CMD_MAKE}
                    BUILD_IN_SOURCE 1
		    CONFIGURE_COMMAND ./bootstrap && ./configure
                    INSTALL_COMMAND "")

set (LYAML_SRC "${PROJECT_BINARY_DIR}/lyaml-prefix/src/lyaml/ext/yaml")
set(LYAML_LIB "${LYAML_SRC}/.libs/yaml.a")
ExternalProject_Add(lyaml
		    URL "http://download.draios.com/dependencies/lyaml-release-v6.0.tar.gz"
                    URL_MD5 "dc3494689a0dce7cf44e7a99c72b1f30"
                    BUILD_COMMAND ${CMD_MAKE}
                    BUILD_IN_SOURCE 1
		    CONFIGURE_COMMAND ./configure --enable-static LIBS=-L../../../libyaml-prefix/src/libyaml/src/.libs CFLAGS=-I../../../libyaml-prefix/src/libyaml/include CPPFLAGS=-I../../../libyaml-prefix/src/libyaml/include LUA_INCLUDE=-I../../../luajit-prefix/src/luajit/src LUA=../../../luajit-prefix/src/luajit/src/luajit
                    INSTALL_COMMAND sh -c "cp -R ${PROJECT_BINARY_DIR}/lyaml-prefix/src/lyaml/lib/* ${PROJECT_SOURCE_DIR}/userspace/engine/lua")

install(FILES falco.yaml
	DESTINATION "${FALCO_ETC_DIR}")

add_subdirectory("${SYSDIG_DIR}/driver" "${PROJECT_BINARY_DIR}/driver")
add_subdirectory("${SYSDIG_DIR}/userspace/libscap" "${PROJECT_BINARY_DIR}/userspace/libscap")
add_subdirectory("${SYSDIG_DIR}/userspace/libsinsp" "${PROJECT_BINARY_DIR}/userspace/libsinsp")

add_subdirectory(scripts)
set(FALCO_SINSP_LIBRARY sinsp)
set(FALCO_SHARE_DIR share/falco)
add_subdirectory(userspace/engine)
add_subdirectory(userspace/falco)


set(CPACK_PACKAGE_NAME "${PACKAGE_NAME}")
set(CPACK_PACKAGE_VENDOR "Sysdig Inc.")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "falco, a system-level activity monitoring tool")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/scripts/description.txt")
set(CPACK_PACKAGE_VERSION "${FALCO_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PROJECT_CONFIG_FILE "${PROJECT_SOURCE_DIR}/CMakeCPackOptions.cmake")
set(CPACK_STRIP_FILES "ON")
set(CPACK_PACKAGE_RELOCATABLE "OFF")

set(CPACK_GENERATOR DEB RPM TGZ)

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Sysdig <support@sysdig.com>")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "http://www.sysdig.org")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "sysdig")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${PROJECT_SOURCE_DIR}/scripts/debian/postinst;${PROJECT_SOURCE_DIR}/scripts/debian/prerm;${PROJECT_SOURCE_DIR}/scripts/debian/postrm")

set(CPACK_RPM_PACKAGE_LICENSE "GPLv2")
set(CPACK_RPM_PACKAGE_URL "http://www.sysdig.org")
set(CPACK_RPM_PACKAGE_REQUIRES "sysdig")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postuninstall")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION /usr/src /usr/share/man /usr/share/man/man8 /etc /usr /usr/bin /usr/share /etc/rc.d /etc/rc.d/init.d )
set(CPACK_RPM_PACKAGE_RELOCATABLE "OFF")

include(CPack)
