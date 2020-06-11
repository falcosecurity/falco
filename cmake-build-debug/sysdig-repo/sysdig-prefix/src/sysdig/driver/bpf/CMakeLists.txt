#
# Copyright (c) 2013-2018 Draios Inc. dba Sysdig.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

configure_file(../driver_config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/../driver_config.h)

option(BUILD_BPF "Build the BPF driver on Linux" OFF)

if(BUILD_BPF)
	add_custom_target(bpf ALL
		COMMAND make
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different probe.o "${CMAKE_CURRENT_BINARY_DIR}"
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
		VERBATIM)
endif()

install(FILES
	bpf_helpers.h
	filler_helpers.h
	fillers.h
	Makefile
	maps.h
	plumbing_helpers.h
	probe.c
	quirks.h
	ring_helpers.h
	types.h
	DESTINATION "src/${PACKAGE_NAME}-${PROBE_VERSION}/bpf"
	COMPONENT agent-kmodule)
