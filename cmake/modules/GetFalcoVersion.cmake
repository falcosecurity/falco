# Retrieve git ref and commit hash
include(GetGitRevisionDescription)
get_git_head_revision(FALCO_REF FALCO_HASH)

# Create the falco version variable according to git index
if(NOT FALCO_VERSION)
  string(STRIP "${FALCO_HASH}" FALCO_HASH)
  # Try to obtain the exact git tag
  git_get_exact_tag(FALCO_TAG)
  if(NOT FALCO_TAG)
    # Obtain the closest tag
    git_describe(FALCO_VERSION "--abbrev=0" "--tags") # suppress the long format
    # Fallback version
    if(FALCO_VERSION MATCHES "NOTFOUND$")
      set(FALCO_VERSION "0.0.0")
    endif()
    # TODO(leodido) > Construct the prerelease part (semver 2) Construct the Build metadata part (semver 2)
    if(NOT FALCO_HASH MATCHES "NOTFOUND$")
      string(SUBSTRING "${FALCO_HASH}" 0 7 FALCO_VERSION_BUILD)
      # Check whether there are uncommitted changes or not
      git_local_changes(FALCO_CHANGES)
      if(FALCO_CHANGES STREQUAL "DIRTY")
        string(TOLOWER "${FALCO_CHANGES}" FALCO_CHANGES)
        set(FALCO_VERSION_BUILD "${FALCO_VERSION_BUILD}.${FALCO_CHANGES}")
      endif()
    endif()
    # Append the build metadata part (semver 2)
    if(FALCO_VERSION_BUILD)
      set(FALCO_VERSION "${FALCO_VERSION}+${FALCO_VERSION_BUILD}")
    endif()
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
      "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)-((0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)\\.(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)*).*"
      "\\4"
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
