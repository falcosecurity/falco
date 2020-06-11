#
# Copyright (c) 2013-2018 Draios Inc. dba Sysdig.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

option(BUILD_DRIVER "Build the driver on Linux" ON)
option(ENABLE_DKMS "Enable DKMS on Linux" ON)

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
#    trigger the actual build. This step cannot know that our Makefile has
#    a different name.
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

configure_file(dkms.conf.in src/dkms.conf)
configure_file(Makefile.in src/Makefile)
configure_file(driver_config.h.in src/driver_config.h)

set(DRIVER_SOURCES
	dynamic_params_table.c
	event_table.c
	fillers_table.c
	flags_table.c
	main.c
	ppm.h
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
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${PROBE_NAME}.ko "${CMAKE_CURRENT_BINARY_DIR}"
		WORKING_DIRECTORY src
		VERBATIM)
else()
	add_custom_target(driver
		COMMAND ${MAKE_COMMAND}
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${PROBE_NAME}.ko "${CMAKE_CURRENT_BINARY_DIR}"
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
		DESTINATION "src/${PACKAGE_NAME}-${PROBE_VERSION}"
		COMPONENT agent-kmodule)

endif()

add_subdirectory(bpf)
