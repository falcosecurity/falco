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
include(CheckSymbolExists)

set(
  LIBHAWK_SOURCES
  lifecycle.cpp
)

set(
  LIBHAWK_PUBLIC_INCLUDES
  hawk.h
)

set(LIBHAWK_INCLUDE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)

add_library(libhawk STATIC ${LIBHAWK_SOURCES})

if(DEFINED LIBHAWK_LIBRARIES)
  message(STATUS "Using externally provided libhawk plugins: ${LIBHAWK_LIBRARIES}")
  target_link_libraries(libhawk ${LIBHAWK_LIBRARIES})
endif()

#todo: we want to provide a default version of the libhawk plugin functions
# we need to manage the situation where the user only provides parts of it and not others
install(
  FILES ${LIBHAWK_PUBLIC_INCLUDES}
  DESTINATION "${FALCO_SHARE_DIR}"
)
