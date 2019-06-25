set(FALCO_TESTS_SOURCES
    TestBase.cpp)

set(FALCO_TESTED_LIBRARIES
    falco_engine)

option(FALCO_BUILD_TESTS "Determines whether to build tests." OFF)

if(FALCO_BUILD_TESTS)
    enable_testing()
    if(NOT TARGET catch)
        include(FindCatch)
    endif()

	add_executable(falco_test ${FALCO_TESTS_SOURCES})

	target_link_libraries(falco_test PUBLIC ${FALCO_TESTED_LIBRARIES} catch)

	include(CTest)
	include(Catch)
	catch_discover_tests(falco_test)

	add_custom_target(tests COMMAND ${CMAKE_CTEST_COMMAND} DEPENDS falco_test)
endif()
