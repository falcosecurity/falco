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
if (NOT USE_BUNDLED_DEPS)
    find_path(JQ_INCLUDE jq.h PATH_SUFFIXES jq)
    find_library(JQ_LIB NAMES jq)
    if (JQ_INCLUDE AND JQ_LIB)
        message(STATUS "Found jq: include: ${JQ_INCLUDE}, lib: ${JQ_LIB}")
    else ()
        message(FATAL_ERROR "Couldn't find system jq")
    endif ()
else ()
    set(JQ_SRC "${PROJECT_BINARY_DIR}/jq-prefix/src/jq")
    message(STATUS "Using bundled jq in '${JQ_SRC}'")
    set(JQ_INCLUDE "${JQ_SRC}")
    set(JQ_INSTALL_DIR "${JQ_SRC}/target")
    set(JQ_LIB "${JQ_INSTALL_DIR}/lib/libjq.a")
    set(ONIGURUMA_LIB "${JQ_INSTALL_DIR}/lib/libonig.a")

    ExternalProject_Add(
            jq
            URL "https://github.com/stedolan/jq/releases/download/jq-1.6/jq-1.6.tar.gz"
            URL_HASH "SHA256=5de8c8e29aaa3fb9cc6b47bb27299f271354ebb72514e3accadc7d38b5bbaa72"
            CONFIGURE_COMMAND autoreconf -fi && ./configure --disable-maintainer-mode --enable-all-static --disable-dependency-tracking --with-oniguruma=builtin --prefix=${JQ_INSTALL_DIR}
            BUILD_COMMAND ${CMD_MAKE} LDFLAGS=-all-static
            BUILD_IN_SOURCE 1
            INSTALL_COMMAND ${CMD_MAKE} install)
endif ()
