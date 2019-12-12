#
# Copyright (C) 2019 The Falco Authors.
#
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#
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
if(GRPC_INCLUDE AND GRPC_LIB AND GRPCPP_LIB)
	message(STATUS "Found grpc: include: ${GRPC_INCLUDE}, C lib: ${GRPC_LIB}, C++ lib: ${GRPCPP_LIB}")
else()
	message(FATAL_ERROR "Couldn't find system grpc")
endif()
find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin)
if(NOT GRPC_CPP_PLUGIN)
	message(FATAL_ERROR "System grpc_cpp_plugin not found")
endif()
