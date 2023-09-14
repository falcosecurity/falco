# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
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

function(copy_files_to_build_dir source_files targetsuffix)

  set(build_files)

  foreach(file_path ${source_files})
	  get_filename_component(trace_file ${file_path} NAME)
	  list(APPEND build_files ${CMAKE_CURRENT_BINARY_DIR}/${trace_file})
  endforeach()

  add_custom_target(copy-files-${targetsuffix} ALL
	  DEPENDS ${build_files})

  add_custom_command(OUTPUT ${build_files}
	  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${source_files} ${CMAKE_CURRENT_BINARY_DIR}
	  DEPENDS ${source_files})

endfunction()
