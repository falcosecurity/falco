# Install script for directory: /home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver

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
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/src/falco-96bd9bc560f67742738eb7255aeb4d03046b8045" TYPE FILE FILES
    "/home/nova/falco/falco/cmake-build-debug/driver/src/Makefile"
    "/home/nova/falco/falco/cmake-build-debug/driver/src/dkms.conf"
    "/home/nova/falco/falco/cmake-build-debug/driver/src/driver_config.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/dynamic_params_table.c"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/event_table.c"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/fillers_table.c"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/flags_table.c"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/main.c"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/ppm.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/ppm_events.c"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/ppm_events.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/ppm_events_public.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/ppm_fillers.c"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/ppm_fillers.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/ppm_flag_helpers.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/ppm_ringbuffer.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/ppm_syscall.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/syscall_table.c"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/ppm_cputime.c"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/ppm_compat_unistd_32.h"
    "/home/nova/falco/falco/cmake-build-debug/sysdig-repo/sysdig-prefix/src/sysdig/driver/ppm_version.h"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/nova/falco/falco/cmake-build-debug/driver/bpf/cmake_install.cmake")

endif()

