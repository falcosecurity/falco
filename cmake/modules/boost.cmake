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

# todo(deepskyblue86): USE_BUNDLED_DEPS

mark_as_advanced(BOOST_INCLUDE_DIR BOOST_URI_LIST BOOST_COMPONENTS BOOST_URL_HASHES BOOST_LIBS)
set(BOOST_INCLUDE_DIR "${PROJECT_BINARY_DIR}/boost-prefix/include/")

set(BOOST_COMPONENTS)
set(BOOST_URL_HASHES)

list(APPEND BOOST_COMPONENTS "multi_index")
list(APPEND BOOST_URL_HASHES "2e887905cf34f189327b672947c24f560065384855ded0c7f0ee240c4fc6cd1a")

list(APPEND BOOST_COMPONENTS "config")
list(APPEND BOOST_URL_HASHES "275a866c973d350f0f6b96b2ad16cbda93405fbe7dbe9bb4f7bad2769cb09c97")

list(APPEND BOOST_COMPONENTS "core")
list(APPEND BOOST_URL_HASHES "a2a2345a8ac1172a346c2eae183a6a27de21b68d6854eef82e808a18d080f14e")

list(APPEND BOOST_COMPONENTS "move")
list(APPEND BOOST_URL_HASHES "5e342c17255f8e2d4c327b2acedd3fb69657a18325a4d9d1449f377867164583")

list(APPEND BOOST_COMPONENTS "static_assert")
list(APPEND BOOST_URL_HASHES "e43b97e8cb48639fd3ebc253414beafc2b53b496fa0d6b71e7d6097780721b56")

list(APPEND BOOST_COMPONENTS "mpl")
list(APPEND BOOST_URL_HASHES "4f33c0051182cae0c7baa1fdf95901e041258fb16153645e754fe1081f7f7eb7")

list(APPEND BOOST_COMPONENTS "preprocessor")
list(APPEND BOOST_URL_HASHES "2c152baf0f281c5fa9c1d8083b4400af776fa7b98af5f58b37bea00cb3550219")

list(APPEND BOOST_COMPONENTS "type_traits")
list(APPEND BOOST_URL_HASHES "30c5e1156422efecbe4be8104dc9fbd0401e4635a37cc3a350a289cf6c40bd7b")

list(APPEND BOOST_COMPONENTS "serialization")
list(APPEND BOOST_URL_HASHES "36594f3df9dff515775a0939019c4ad06f80eb1c714efe3e0361a7549725df74")

list(APPEND BOOST_COMPONENTS "assert")
list(APPEND BOOST_URL_HASHES "aad0c937c384bc8e3d78d0c8aa7725a2c36cb91be9f44b75cad72b15887aeeb4")

list(APPEND BOOST_COMPONENTS "throw_exception")
list(APPEND BOOST_URL_HASHES "02ca41caef50ceea5fa26c3dd6b186e3cb09da2d71ce1aa47d0a9963a2cdf565")

list(APPEND BOOST_COMPONENTS "tuple")
list(APPEND BOOST_URL_HASHES "e18a27b1edfee817c47c7954bf667a823c595ec67a4dcd0b9ae496009f404160")

list(APPEND BOOST_COMPONENTS "utility")
list(APPEND BOOST_URL_HASHES "e970437afee9417126cb6f75eb66b263b1083a20b8468257c19e8e1e052d7cdc")

list(APPEND BOOST_COMPONENTS "foreach")
list(APPEND BOOST_URL_HASHES "b3500dd1e7ca5479ffd3041c97e00f9dd73700e485474593eb572416caeb8b74")

list(APPEND BOOST_COMPONENTS "iterator")
list(APPEND BOOST_URL_HASHES "cfdbcedef006f178024ec6d6eda1f40b6935479dfc14d583ef195ae324f81c31")

list(APPEND BOOST_COMPONENTS "detail")
list(APPEND BOOST_URL_HASHES "4a255a2283e754a9b6ee01afda51b0a220cf5f29b9b3a0c8731e997fc3255318")

list(APPEND BOOST_COMPONENTS "bind")
list(APPEND BOOST_URL_HASHES "f2fe75d76b6aaa7c1d66fc2f1fc5023e8da846f31a3af42479fd22b50044c9d4")

list(APPEND BOOST_COMPONENTS "integer")
list(APPEND BOOST_URL_HASHES "2cc6bb4d73cb06348fda3a21ad6d1c46ef07e7e23daebe5b0a18d4af3a916968")

list(LENGTH BOOST_COMPONENTS list_count)
# range loop is from 0 to n included, decrement
math(EXPR list_count ${list_count}-1)
foreach(i RANGE ${list_count})
  list(GET BOOST_COMPONENTS ${i} component)
  list(GET BOOST_URL_HASHES ${i} hash)

  ExternalProject_Add(${component}
    URL "https://github.com/boostorg/${component}/archive/refs/tags/boost-1.71.0.tar.gz"
    URL_HASH "SHA256=${hash}"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_BINARY_DIR}/${component}-prefix/src/${component}/include ${BOOST_INCLUDE_DIR}
  )
endforeach()

add_custom_target(
  boost ALL
  DEPENDS ${BOOST_COMPONENTS}
)
