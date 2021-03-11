#
# Copyright (C) 2020 The Falco Authors.
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

# Retrieve git ref and commit hash
include(GetGitRevisionDescription)

# Create the falco version variable according to git index
if(NOT FALCO_VERSION)
  string(STRIP "${FALCO_HASH}" FALCO_HASH)
  # Try to obtain the exact git tag
  git_get_exact_tag(FALCO_TAG)
  if(NOT FALCO_TAG)
    # Obtain the closest tag
    git_describe(FALCO_VERSION "--always" "--tags")
    # Fallback version
    if(FALCO_VERSION MATCHES "NOTFOUND$")
      set(FALCO_VERSION "0.0.0")
    endif()
    # Format FALCO_VERSION to be semver with prerelease and build part
    string(REPLACE "-g" "~" FALCO_VERSION "${FALCO_VERSION}")
  else()
    # A tag has been found: use it as the Falco version
    set(FALCO_VERSION "${FALCO_TAG}")
    # Remove the starting "v" in case there is one
    string(REGEX REPLACE "^v(.*)" "\\1" FALCO_VERSION "${FALCO_TAG}")
  endif()
  # TODO(leodido) > ensure Falco version is semver before extracting parts Populate partial version variables
  string(REGEX MATCH "^(0|[1-9][0-9]*)" FALCO_VERSION_MAJOR "${FALCO_VERSION}")
  string(REGEX REPLACE "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\..*" "\\2" FALCO_VERSION_MINOR "${FALCO_VERSION}")
  string(REGEX REPLACE "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*).*" "\\3" FALCO_VERSION_PATCH
                       "${FALCO_VERSION}")
  string(
    REGEX
    REPLACE
      "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)-((0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)(\\.(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*).*"
      "\\5"
      FALCO_VERSION_PRERELEASE
      "${FALCO_VERSION}")
  if(FALCO_VERSION_PRERELEASE STREQUAL "${FALCO_VERSION}")
    set(FALCO_VERSION_PRERELEASE "")
  endif()
  if(NOT FALCO_VERSION_BUILD)
    string(REGEX REPLACE ".*\\+([0-9a-zA-Z-]+(\\.[0-9a-zA-Z-]+)*)" "\\1" FALCO_VERSION_BUILD "${FALCO_VERSION}")
  endif()
  if(FALCO_VERSION_BUILD STREQUAL "${FALCO_VERSION}")
    set(FALCO_VERSION_BUILD "")
  endif()
endif()
message(STATUS "Falco version: ${FALCO_VERSION}")
