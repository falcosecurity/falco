# Install script for directory: /home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/bpf

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "0")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xagent-kmodulex" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/src/falco-96bd9bc560f67742738eb7255aeb4d03046b8045/bpf" TYPE FILE FILES
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/bpf/bpf_helpers.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/bpf/filler_helpers.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/bpf/fillers.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/bpf/Makefile"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/bpf/maps.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/bpf/plumbing_helpers.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/bpf/probe.c"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/bpf/quirks.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/bpf/ring_helpers.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/bpf/types.h"
    )
endif()

