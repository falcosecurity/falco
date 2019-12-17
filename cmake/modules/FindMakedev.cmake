#
# Copyright (C) 2019 The Falco Authors.
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

# This module is used to understand where the makedev function is defined in the glibc in use. see 'man 3 makedev'
# Usage: In your CMakeLists.txt include(FindMakedev)
#
# In your source code:
#
# #if HAVE_SYS_MKDEV_H #include <sys/mkdev.h> #endif #ifdef HAVE_SYS_SYSMACROS_H #include <sys/sysmacros.h> #endif
#
include(${CMAKE_ROOT}/Modules/CheckIncludeFile.cmake)

check_include_file("sys/mkdev.h" HAVE_SYS_MKDEV_H)
check_include_file("sys/sysmacros.h" HAVE_SYS_SYSMACROS_H)

if(HAVE_SYS_MKDEV_H)
  add_definitions(-DHAVE_SYS_MKDEV_H)
endif()
if(HAVE_SYS_SYSMACROS_H)
  add_definitions(-DHAVE_SYS_SYSMACROS_H)
endif()
