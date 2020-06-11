
if(NOT "/home/nova/falco/falco/cmake-build-debug/string-view-lite-prefix/src/string-view-lite-stamp/string-view-lite-gitinfo.txt" IS_NEWER_THAN "/home/nova/falco/falco/cmake-build-debug/string-view-lite-prefix/src/string-view-lite-stamp/string-view-lite-gitclone-lastrun.txt")
  message(STATUS "Avoiding repeated git clone, stamp file is up to date: '/home/nova/falco/falco/cmake-build-debug/string-view-lite-prefix/src/string-view-lite-stamp/string-view-lite-gitclone-lastrun.txt'")
  return()
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} -E rm -rf "/home/nova/falco/falco/cmake-build-debug/string-view-lite-prefix/src/string-view-lite"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to remove directory: '/home/nova/falco/falco/cmake-build-debug/string-view-lite-prefix/src/string-view-lite'")
endif()

# try the clone 3 times in case there is an odd git clone issue
set(error_code 1)
set(number_of_tries 0)
while(error_code AND number_of_tries LESS 3)
  execute_process(
    COMMAND "/usr/bin/git"  clone --no-checkout "https://github.com/martinmoene/string-view-lite.git" "string-view-lite"
    WORKING_DIRECTORY "/home/nova/falco/falco/cmake-build-debug/string-view-lite-prefix/src"
    RESULT_VARIABLE error_code
    )
  math(EXPR number_of_tries "${number_of_tries} + 1")
endwhile()
if(number_of_tries GREATER 1)
  message(STATUS "Had to git clone more than once:
          ${number_of_tries} times.")
endif()
if(error_code)
  message(FATAL_ERROR "Failed to clone repository: 'https://github.com/martinmoene/string-view-lite.git'")
endif()

execute_process(
  COMMAND "/usr/bin/git"  checkout v1.4.0 --
  WORKING_DIRECTORY "/home/nova/falco/falco/cmake-build-debug/string-view-lite-prefix/src/string-view-lite"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to checkout tag: 'v1.4.0'")
endif()

set(init_submodules TRUE)
if(init_submodules)
  execute_process(
    COMMAND "/usr/bin/git"  submodule update --recursive --init 
    WORKING_DIRECTORY "/home/nova/falco/falco/cmake-build-debug/string-view-lite-prefix/src/string-view-lite"
    RESULT_VARIABLE error_code
    )
endif()
if(error_code)
  message(FATAL_ERROR "Failed to update submodules in: '/home/nova/falco/falco/cmake-build-debug/string-view-lite-prefix/src/string-view-lite'")
endif()

# Complete success, update the script-last-run stamp file:
#
execute_process(
  COMMAND ${CMAKE_COMMAND} -E copy
    "/home/nova/falco/falco/cmake-build-debug/string-view-lite-prefix/src/string-view-lite-stamp/string-view-lite-gitinfo.txt"
    "/home/nova/falco/falco/cmake-build-debug/string-view-lite-prefix/src/string-view-lite-stamp/string-view-lite-gitclone-lastrun.txt"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to copy script-last-run stamp file: '/home/nova/falco/falco/cmake-build-debug/string-view-lite-prefix/src/string-view-lite-stamp/string-view-lite-gitclone-lastrun.txt'")
endif()

