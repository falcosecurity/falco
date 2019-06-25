
include(ExternalProject)
set(CATCH_EXTERNAL_URL
    URL https://github.com/catchorg/Catch2/archive/v2.9.1.tar.gz)
    #URL_HASH MD5=2080f4696579351d9323b3b5a8c3c71b)
ExternalProject_Add(catch2
    PREFIX ${CMAKE_BINARY_DIR}/catch2-prefix
    ${CATCH_EXTERNAL_URL}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/catch2-prefix/src/catch2/single_include/catch2/catch.hpp
                                            ${CMAKE_BINARY_DIR}/catch2-prefix/include/catch.hpp
)
add_library(catch INTERFACE)
add_dependencies(catch catch2)
target_include_directories(catch INTERFACE ${CMAKE_BINARY_DIR}/catch2-prefix/include)

