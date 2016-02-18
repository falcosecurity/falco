include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)

if(NOT APPLE)
    include_directories("${CURL_INCLUDE_DIR}")
endif()


include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)

add_executable(digwatch digwatch.cpp)

target_link_libraries(digwatch sinsp)


