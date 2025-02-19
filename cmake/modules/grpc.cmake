# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under
# the License.
#

option(USE_BUNDLED_GRPC "Enable building of the bundled grpc" ${USE_BUNDLED_DEPS})

if(GRPC_INCLUDE)
	# we already have grpc
elseif(NOT USE_BUNDLED_GRPC)
	# gRPC
	find_package(gRPC CONFIG)
	if(gRPC_FOUND)
		message(STATUS "Using gRPC ${gRPC_VERSION}")
		set(GPR_LIB gRPC::gpr)
		set(GRPC_LIB gRPC::grpc)
		set(GRPCPP_LIB gRPC::grpc++)

		# gRPC C++ plugin
		get_target_property(GRPC_CPP_PLUGIN gRPC::grpc_cpp_plugin LOCATION)
		if(NOT GRPC_CPP_PLUGIN)
			message(FATAL_ERROR "System grpc_cpp_plugin not found")
		endif()

		# gRPC include dir + properly handle grpc{++,pp}
		get_target_property(GRPC_INCLUDE gRPC::grpc++ INTERFACE_INCLUDE_DIRECTORIES)
		find_path(
			GRPCXX_INCLUDE
			NAMES grpc++/grpc++.h
			PATHS ${GRPC_INCLUDE}
		)
		if(NOT GRPCXX_INCLUDE)
			find_path(
				GRPCPP_INCLUDE
				NAMES grpcpp/grpcpp.h
				PATHS ${GRPC_INCLUDE}
			)
			add_definitions(-DGRPC_INCLUDE_IS_GRPCPP=1)
		endif()
	else()
		# Fallback to manually find libraries; Some distro, namely Ubuntu focal, do not install gRPC
		# config cmake module
		find_library(GPR_LIB NAMES gpr)
		if(GPR_LIB)
			message(STATUS "Found gpr lib: ${GPR_LIB}")
		else()
			message(FATAL_ERROR "Couldn't find system gpr")
		endif()
		find_path(GRPCXX_INCLUDE NAMES grpc++/grpc++.h)
		if(GRPCXX_INCLUDE)
			set(GRPC_INCLUDE ${GRPCXX_INCLUDE})
		else()
			find_path(GRPCPP_INCLUDE NAMES grpcpp/grpcpp.h)
			set(GRPC_INCLUDE ${GRPCPP_INCLUDE})
			add_definitions(-DGRPC_INCLUDE_IS_GRPCPP=1)
		endif()
		find_library(GRPC_LIB NAMES grpc)
		find_library(GRPCPP_LIB NAMES grpc++)
		if(GRPC_INCLUDE
		   AND GRPC_LIB
		   AND GRPCPP_LIB
		)
			message(
				STATUS
					"Found grpc: include: ${GRPC_INCLUDE}, C lib: ${GRPC_LIB}, C++ lib: ${GRPCPP_LIB}"
			)
		else()
			message(FATAL_ERROR "Couldn't find system grpc")
		endif()
		find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin)
		if(NOT GRPC_CPP_PLUGIN)
			message(FATAL_ERROR "System grpc_cpp_plugin not found")
		endif()
	endif()
else()
	include(cares)
	include(protobuf)
	include(zlib)
	include(openssl)
	if(BUILD_SHARED_LIBS)
		set(GRPC_OPENSSL_STATIC_LIBS_OPTION FALSE)
	else()
		set(GRPC_OPENSSL_STATIC_LIBS_OPTION TRUE)
	endif()
	include(re2)
	set(GRPC_SRC "${PROJECT_BINARY_DIR}/grpc-prefix/src/grpc")
	set(GRPC_INSTALL_DIR "${GRPC_SRC}/target")
	set(GRPC_INCLUDE "${GRPC_INSTALL_DIR}/include" "${GRPC_SRC}/third_party/abseil-cpp")
	set(GPR_LIB "${GRPC_SRC}/libgpr.a")
	set(GRPC_LIB "${GRPC_SRC}/libgrpc.a")
	set(GRPCPP_LIB "${GRPC_SRC}/libgrpc++.a")
	set(GRPC_CPP_PLUGIN "${GRPC_SRC}/grpc_cpp_plugin")
	set(GRPC_MAIN_LIBS "")
	list(
		APPEND
		GRPC_MAIN_LIBS
		"${GPR_LIB}"
		"${GRPC_LIB}"
		"${GRPCPP_LIB}"
		"${GRPC_SRC}/libgrpc++_alts.a"
		"${GRPC_SRC}/libgrpc++_error_details.a"
		"${GRPC_SRC}/libgrpc++_reflection.a"
		"${GRPC_SRC}/libgrpc++_unsecure.a"
		"${GRPC_SRC}/libgrpc_plugin_support.a"
		"${GRPC_SRC}/libgrpc_unsecure.a"
		"${GRPC_SRC}/libgrpcpp_channelz.a"
	)

	get_filename_component(PROTOC_DIR ${PROTOC} PATH)

	if(NOT TARGET grpc)
		message(STATUS "Using bundled grpc in '${GRPC_SRC}'")

		# fixme(leogr): this workaround is required to inject the missing deps (built by gRCP
		# cmakefiles) into target_link_libraries later note: the list below is manually generated
		# starting from the output of pkg-config --libs grpc++
		set(GRPC_LIBRARIES "")
		list(
			APPEND
			GRPC_LIBRARIES
			"${GRPC_SRC}/libaddress_sorting.a"
			"${GRPC_SRC}/libupb.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/hash/libabsl_hash.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/hash/libabsl_city.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/hash/libabsl_low_level_hash.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/container/libabsl_raw_hash_set.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/container/libabsl_hashtablez_sampler.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/status/libabsl_statusor.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/status/libabsl_status.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/strings/libabsl_cord.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/strings/libabsl_cordz_functions.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/profiling/libabsl_exponential_biased.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/types/libabsl_bad_optional_access.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/types/libabsl_bad_variant_access.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/strings/libabsl_str_format_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/synchronization/libabsl_synchronization.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/synchronization/libabsl_graphcycles_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/debugging/libabsl_stacktrace.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/debugging/libabsl_symbolize.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/debugging/libabsl_debugging_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/debugging/libabsl_demangle_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/base/libabsl_malloc_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/time/libabsl_time.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/time/libabsl_civil_time.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/strings/libabsl_strings.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/strings/libabsl_strings_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/base/libabsl_base.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/base/libabsl_spinlock_wait.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/numeric/libabsl_int128.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/base/libabsl_throw_delegate.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/base/libabsl_raw_logging_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/base/libabsl_log_severity.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/time/libabsl_time_zone.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/strings/libabsl_cord_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/strings/libabsl_cordz_info.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/strings/libabsl_cordz_handle.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/random/libabsl_random_internal_pool_urbg.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/random/libabsl_random_internal_randen.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/random/libabsl_random_internal_randen_hwaes.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/random/libabsl_random_internal_randen_hwaes_impl.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/random/libabsl_random_internal_randen_slow.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/random/libabsl_random_internal_seed_material.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/random/libabsl_random_internal_platform.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/random/libabsl_random_seed_gen_exception.a"
		)

		# Make abseil-cpp build compatible with gcc-13 See
		# https://patchwork.yoctoproject.org/project/oe/patch/20230518093301.2938164-1-Martin.Jansa@gmail.com/
		# TO BE DROPPED once we finally upgrade grpc...
		set(GRPC_PATCH_CMD
			sh
			-c
			"sed -i '20s/^/#include <cstdint>/' ${GRPC_SRC}/third_party/abseil-cpp/absl/strings/internal/str_format/extension.h"
		)

		# Zig workaround: Add a PATCH_COMMAND to grpc cmake to fixup emitted -march by abseil-cpp
		# cmake module, making it use a name understood by zig for arm64. See
		# https://github.com/abseil/abseil-cpp/blob/master/absl/copts/GENERATED_AbseilCopts.cmake#L226.
		if(CMAKE_C_COMPILER MATCHES "zig")
			message(STATUS "Enabling zig workaround for abseil-cpp")
			set(GRPC_PATCH_CMD
				${GRPC_PATCH_CMD}
				&&
				sh
				-c
				"sed -i 's/armv8-a/cortex_a57/g' ${GRPC_SRC}/third_party/abseil-cpp/absl/copts/GENERATED_AbseilCopts.cmake"
			)
		endif()

		ExternalProject_Add(
			grpc
			PREFIX "${PROJECT_BINARY_DIR}/grpc-prefix"
			DEPENDS openssl protobuf c-ares zlib re2
			GIT_REPOSITORY https://github.com/grpc/grpc.git
			GIT_TAG v1.44.0
			GIT_SUBMODULES "third_party/abseil-cpp"
			CMAKE_CACHE_ARGS
				-DCMAKE_INSTALL_PREFIX:PATH=${GRPC_INSTALL_DIR}
				-DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
				-DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=${ENABLE_PIC}
				-DgRPC_INSTALL:BOOL=OFF
				# disable unused stuff
				-DgRPC_BUILD_TESTS:BOOL=OFF
				-DgRPC_BUILD_CSHARP_EXT:BOOL=OFF
				-DgRPC_BUILD_GRPC_CSHARP_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_NODE_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_OBJECTIVE_C_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_PHP_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_PYTHON_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_RUBY_PLUGIN:BOOL=OFF
				# deps provided by us
				# https://github.com/grpc/grpc/blob/v1.32.0/cmake/modules/Findc-ares.cmake
				-DgRPC_CARES_PROVIDER:STRING=package
				-Dc-ares_DIR:PATH=${CARES_SRC}
				-Dc-ares_INCLUDE_DIR:PATH=${CARES_INCLUDE}
				-Dc-ares_LIBRARY:PATH=${CARES_LIB}
				# https://cmake.org/cmake/help/v3.6/module/FindProtobuf.html
				-DgRPC_PROTOBUF_PROVIDER:STRING=package
				-DCMAKE_CXX_FLAGS:STRING=-I${PROTOBUF_INCLUDE}
				-DProtobuf_INCLUDE_DIR:PATH=${PROTOBUF_INCLUDE}
				-DProtobuf_LIBRARY:PATH=${PROTOBUF_LIB}
				-DProtobuf_PROTOC_LIBRARY:PATH=${PROTOC_LIB}
				-DProtobuf_PROTOC_EXECUTABLE:PATH=${PROTOC}
				# https://cmake.org/cmake/help/v3.6/module/FindOpenSSL.html
				-DgRPC_SSL_PROVIDER:STRING=package
				-DOPENSSL_ROOT_DIR:PATH=${OPENSSL_INSTALL_DIR}
				-DOPENSSL_USE_STATIC_LIBS:BOOL=${GRPC_OPENSSL_STATIC_LIBS_OPTION}
				# https://cmake.org/cmake/help/v3.6/module/FindZLIB.html
				-DgRPC_ZLIB_PROVIDER:STRING=package
				-DZLIB_ROOT:STRING=${ZLIB_SRC}
				# RE2
				-DgRPC_RE2_PROVIDER:STRING=package
				-Dre2_DIR:PATH=${RE2_DIR}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${GRPC_LIB} ${GRPCPP_LIB} ${GPR_LIB} ${GRPC_LIBRARIES}
			# Keep installation files into the local ${GRPC_INSTALL_DIR} since here is the case when
			# we are embedding gRPC
			UPDATE_COMMAND ""
			PATCH_COMMAND ${GRPC_PATCH_CMD}
			INSTALL_COMMAND DESTDIR= ${CMAKE_MAKE_PROGRAM} install
		)
		install(
			FILES ${GRPC_MAIN_LIBS}
			DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps"
		)
		install(
			FILES ${GRPC_LIBRARIES}
			DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps"
		)
		install(
			DIRECTORY "${GRPC_SRC}/target/include/"
			DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps"
		)
	endif()
endif()

if(NOT TARGET grpc)
	add_custom_target(grpc)
endif()

include_directories("${GRPC_INCLUDE}")
