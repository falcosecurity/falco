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

# create the reports folder
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/static-analysis-reports)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/static-analysis-reports/cppcheck)

# cppcheck
mark_as_advanced(CPPCHECK CPPCHECK_HTMLREPORT)
find_program(CPPCHECK cppcheck)
find_program(CPPCHECK_HTMLREPORT cppcheck-htmlreport)

if(NOT CPPCHECK)
  message(STATUS "cppcheck command not found, static code analysis using cppcheck will not be available.")
else()
  message(STATUS "cppcheck found at: ${CPPCHECK}")
  # we are aware that cppcheck can be run
  # along with the software compilation in a single step
  # using the CMAKE_CXX_CPPCHECK variables.
  # However, for practical needs we want to keep the
  # two things separated and have a specific target for it.
  # Our cppcheck target reads the compilation database produced by CMake
  set(CMAKE_EXPORT_COMPILE_COMMANDS On)
  add_custom_target(
      cppcheck
      COMMAND ${CPPCHECK}
      "--enable=all"
      "--force"
      "--inconclusive"
      "--inline-suppr" # allows to specify suppressions directly in source code
      "--xml" # we want to generate a report
      "--output-file=${CMAKE_CURRENT_BINARY_DIR}/static-analysis-reports/cppcheck/cppcheck.xml" # generate the report under the reports folder in the build folder
      "-i${CMAKE_CURRENT_BINARY_DIR}"# exclude the build folder
      "${CMAKE_SOURCE_DIR}"
  )
endif() # CPPCHECK

if(NOT CPPCHECK_HTMLREPORT)
  message(STATUS "cppcheck-htmlreport command not found, will not be able to produce html reports for cppcheck results")
else()
  message(STATUS "cppcheck-htmlreport found at: ${CPPCHECK_HTMLREPORT}")
  add_custom_target(
    cppcheck_htmlreport
    COMMAND ${CPPCHECK_HTMLREPORT} --title=${CMAKE_PROJECT_NAME} --report-dir=${CMAKE_CURRENT_BINARY_DIR}/static-analysis-reports/cppcheck --file=static-analysis-reports/cppcheck/cppcheck.xml)
endif() # CPPCHECK_HTMLREPORT
