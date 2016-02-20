include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories("${LUAJIT_INCLUDE_DIR}")

if(NOT APPLE)
    include_directories("${CURL_INCLUDE_DIR}")
endif()


include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)

add_executable(digwatch rules.cpp digwatch.cpp)

target_link_libraries(digwatch sinsp)


