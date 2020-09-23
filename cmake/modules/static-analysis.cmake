# create the reports folder
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/static-analysis-reports)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/static-analysis-reports/cppcheck)

# cppcheck
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
      "--project=${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json" # use the compilation database as source
      "--quiet"
      "--xml" # we want to generate a report
      "--output-file=${CMAKE_CURRENT_BINARY_DIR}/static-analysis-reports/cppcheck/cppcheck.xml" # generate the report under the reports folder in the build folder
      "-i${CMAKE_CURRENT_BINARY_DIR}"# exclude the build folder
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
