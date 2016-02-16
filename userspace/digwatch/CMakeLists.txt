include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)

include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)

add_executable(digwatch digwatch.cpp)

target_link_libraries(digwatch sinsp)


