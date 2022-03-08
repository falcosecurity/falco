#
# Copyright (C) 2022 The Falco Authors.
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

mark_as_advanced(BOOST_INCLUDE_DIR)
set(BOOST_INCLUDE_DIR "${PROJECT_BINARY_DIR}/boost-prefix/include/")

# todo(deepskyblue86): USE_BUNDLED_DEPS

ExternalProject_Add(multi_index
  URL "https://github.com/boostorg/multi_index/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=2e887905cf34f189327b672947c24f560065384855ded0c7f0ee240c4fc6cd1a"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/multi_index-prefix/src/multi_index/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(config
  URL "https://github.com/boostorg/config/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=275a866c973d350f0f6b96b2ad16cbda93405fbe7dbe9bb4f7bad2769cb09c97"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/config-prefix/src/config/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(core
  URL "https://github.com/boostorg/core/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=a2a2345a8ac1172a346c2eae183a6a27de21b68d6854eef82e808a18d080f14e"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/core-prefix/src/core/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(move
  URL "https://github.com/boostorg/move/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=5e342c17255f8e2d4c327b2acedd3fb69657a18325a4d9d1449f377867164583"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/move-prefix/src/move/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(static_assert
  URL "https://github.com/boostorg/static_assert/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=e43b97e8cb48639fd3ebc253414beafc2b53b496fa0d6b71e7d6097780721b56"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/static_assert-prefix/src/static_assert/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(mpl
  URL "https://github.com/boostorg/mpl/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=4f33c0051182cae0c7baa1fdf95901e041258fb16153645e754fe1081f7f7eb7"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/mpl-prefix/src/mpl/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(preprocessor
  URL "https://github.com/boostorg/preprocessor/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=2c152baf0f281c5fa9c1d8083b4400af776fa7b98af5f58b37bea00cb3550219"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/preprocessor-prefix/src/preprocessor/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(type_traits
  URL "https://github.com/boostorg/type_traits/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=30c5e1156422efecbe4be8104dc9fbd0401e4635a37cc3a350a289cf6c40bd7b"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/type_traits-prefix/src/type_traits/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(serialization
  URL "https://github.com/boostorg/serialization/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=36594f3df9dff515775a0939019c4ad06f80eb1c714efe3e0361a7549725df74"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/serialization-prefix/src/serialization/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(assert
  URL "https://github.com/boostorg/assert/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=aad0c937c384bc8e3d78d0c8aa7725a2c36cb91be9f44b75cad72b15887aeeb4"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/assert-prefix/src/assert/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(throw_exception
  URL "https://github.com/boostorg/throw_exception/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=02ca41caef50ceea5fa26c3dd6b186e3cb09da2d71ce1aa47d0a9963a2cdf565"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/throw_exception-prefix/src/throw_exception/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(tuple
  URL "https://github.com/boostorg/tuple/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=e18a27b1edfee817c47c7954bf667a823c595ec67a4dcd0b9ae496009f404160"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/tuple-prefix/src/tuple/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(utility
  URL "https://github.com/boostorg/utility/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=e970437afee9417126cb6f75eb66b263b1083a20b8468257c19e8e1e052d7cdc"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/utility-prefix/src/utility/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(foreach
  URL "https://github.com/boostorg/foreach/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=b3500dd1e7ca5479ffd3041c97e00f9dd73700e485474593eb572416caeb8b74"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/foreach-prefix/src/foreach/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(iterator
  URL "https://github.com/boostorg/iterator/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=cfdbcedef006f178024ec6d6eda1f40b6935479dfc14d583ef195ae324f81c31"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/iterator-prefix/src/iterator/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(detail
  URL "https://github.com/boostorg/detail/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=4a255a2283e754a9b6ee01afda51b0a220cf5f29b9b3a0c8731e997fc3255318"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/detail-prefix/src/detail/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(bind
  URL "https://github.com/boostorg/bind/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=f2fe75d76b6aaa7c1d66fc2f1fc5023e8da846f31a3af42479fd22b50044c9d4"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/bind-prefix/src/bind/include ${BOOST_INCLUDE_DIR}
)

ExternalProject_Add(integer
  URL "https://github.com/boostorg/integer/archive/refs/tags/boost-1.71.0.tar.gz"
  URL_HASH "SHA256=2cc6bb4d73cb06348fda3a21ad6d1c46ef07e7e23daebe5b0a18d4af3a916968"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/integer-prefix/src/integer/include ${BOOST_INCLUDE_DIR}
)

add_custom_target(
  boost ALL
  DEPENDS
    multi_index
    config
    core
    static_assert
    mpl
    preprocessor
    type_traits
    serialization
    assert
    throw_exception
    tuple
    utility
    foreach
    iterator
    detail
    bind
    integer
)
