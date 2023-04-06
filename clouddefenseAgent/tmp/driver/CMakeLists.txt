#
# Copyright (C) 2022 The Falco Authors.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

cmake_minimum_required(VERSION 3.12)
project(driver)

set(TARGET_ARCH ${CMAKE_HOST_SYSTEM_PROCESSOR})
if((NOT TARGET_ARCH STREQUAL "x86_64") AND
   (NOT TARGET_ARCH STREQUAL "aarch64") AND
   (NOT TARGET_ARCH STREQUAL "s390x"))
	message(WARNING "Target architecture not officially supported by our drivers!")
endif()

# Load current kernel version
execute_process(COMMAND uname -r OUTPUT_VARIABLE UNAME_RESULT OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REGEX MATCH "[0-9]+.[0-9]+" LINUX_KERNEL_VERSION ${UNAME_RESULT})
message(STATUS  "Kernel version: ${UNAME_RESULT}")

# Check minimum kernel version
set(kmod_min_kver_map_x86_64 2.6)
set(kmod_min_kver_map_aarch64 3.16)
set(kmod_min_kver_map_s390x 2.6)
if (LINUX_KERNEL_VERSION VERSION_LESS ${kmod_min_kver_map_${TARGET_ARCH}})
	message(WARNING "[KMOD] To run this driver you need a Linux kernel version >= ${kmod_min_kver_map_${TARGET_ARCH}} but actual kernel version is: ${UNAME_RESULT}")
endif()

option(BUILD_DRIVER "Build the driver on Linux" ON)
option(ENABLE_DKMS "Enable DKMS on Linux" ON)

if(NOT DEFINED DRIVER_VERSION)
	message(FATAL_ERROR
		"No DRIVER_VERSION set.\nPlease either explicitly set it or build the root project 'falcosecurity/libs' from a git working directory."
	)
endif()

if(NOT DEFINED DRIVER_COMPONENT_NAME)
	set(DRIVER_COMPONENT_NAME "scap-driver")
endif()

if(NOT DEFINED DRIVER_PACKAGE_NAME)
	set(DRIVER_PACKAGE_NAME "scap")
endif()

if(NOT DEFINED DRIVER_NAME)
	set(DRIVER_NAME "scap")
endif()

if(NOT DEFINED DRIVER_DEVICE_NAME)
	set(DRIVER_DEVICE_NAME "${DRIVER_NAME}")
endif()

# The driver build process is somewhat involved because we use the same
# sources for building the driver locally and for shipping as a DKMS module.
#
# We need a single directory with the following files inside:
# - all the driver *.c/*.h sources
# - Makefile generated from Makefile.in
# - driver_config.h generated from driver_config.h.in
#
# The Makefile _must_ be called just Makefile (and not e.g. Makefile.dkms)
# because of the module build process, which looks like this:
# 1. The user (or some script) runs make in our driver directory
# 2. Our Makefile runs the Makefile from kernel sources/headers
# 3. The kernel Makefile calls our original Makefile again, with options that
# trigger the actual build. This step cannot know that our Makefile has
# a different name.
#
# (DKMS needs a Makefile called Makefile as well).
#
# The files need to be in a single directory because we cannot know where
# the sources will be built (especially by DKMS) so we cannot put _any_ paths
# in the Makefile.
#
# The chosen directory must not be ${CMAKE_CURRENT_BINARY_DIR} because CMake
# puts its own generated Makefile in there, so we (arbitrarily) choose
# ${CMAKE_CURRENT_BINARY_DIR}/src. To maintain compatibility with older versions,
# after the build we copy the compiled module one directory up,
# to ${CMAKE_CURRENT_BINARY_DIR}.
include(compute_versions RESULT_VARIABLE RESULT)
if(RESULT STREQUAL NOTFOUND)
  message(FATAL_ERROR "problem with compute_versions.cmake in ${CMAKE_MODULE_PATH}")
endif()
compute_versions(API_VERSION SCHEMA_VERSION)

configure_file(dkms.conf.in src/dkms.conf)
configure_file(Makefile.in src/Makefile)
configure_file(driver_config.h.in src/driver_config.h)

set(DRIVER_SOURCES
	dynamic_params_table.c
	event_table.c
	fillers_table.c
	flags_table.c
	kernel_hacks.h
	feature_gates.h
	main.c
	ppm.h
	ppm_api_version.h
	ppm_events.c
	ppm_events.h
	ppm_events_public.h
	ppm_fillers.c
	ppm_fillers.h
	ppm_flag_helpers.h
	ppm_ringbuffer.h
	ppm_syscall.h
	syscall_table.c
	ppm_cputime.c
	ppm_compat_unistd_32.h
	ppm_version.h
	systype_compat.h
	ppm_tp.h
	ppm_tp.c
)

foreach(FILENAME IN LISTS DRIVER_SOURCES)
	configure_file(${FILENAME} src/${FILENAME} COPYONLY)
endforeach()

# make can be self-referenced as $(MAKE) only from Makefiles but this
# triggers syntax errors with other generators such as Ninja
if(${CMAKE_GENERATOR} STREQUAL "Unix Makefiles")
	set(MAKE_COMMAND "$(MAKE)")
else()
	set(MAKE_COMMAND "make")
endif()

# This if/else is needed because you currently cannot manipulate dependencies
# of built-in targets like "all" in CMake:
# http://public.kitware.com/Bug/view.php?id=8438
if(BUILD_DRIVER)
	add_custom_target(driver ALL
		COMMAND ${MAKE_COMMAND}
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${DRIVER_NAME}.ko "${CMAKE_CURRENT_BINARY_DIR}"
		WORKING_DIRECTORY src
		VERBATIM)
else()
	add_custom_target(driver
		COMMAND ${MAKE_COMMAND}
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${DRIVER_NAME}.ko "${CMAKE_CURRENT_BINARY_DIR}"
		WORKING_DIRECTORY src
		VERBATIM)
endif()

add_custom_target(install_driver
	COMMAND ${MAKE_COMMAND} install
	DEPENDS driver
	WORKING_DIRECTORY src
	VERBATIM)

if(ENABLE_DKMS)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/src/Makefile
		${CMAKE_CURRENT_BINARY_DIR}/src/dkms.conf
		${CMAKE_CURRENT_BINARY_DIR}/src/driver_config.h
		${DRIVER_SOURCES}
		DESTINATION "src/${DRIVER_PACKAGE_NAME}-${DRIVER_VERSION}"
		COMPONENT ${DRIVER_COMPONENT_NAME})
endif()

add_subdirectory(bpf)
