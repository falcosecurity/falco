include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories("${LUAJIT_INCLUDE}")

include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories("${PROJECT_BINARY_DIR}/userspace/digwatch")
include_directories("${CURL_INCLUDE_DIR}")
include_directories("${LPEG_SRC}")

add_executable(digwatch formats.cpp fields.cpp rules.cpp syslog.cpp digwatch.cpp)

target_link_libraries(digwatch sinsp)
target_link_libraries(digwatch "${LPEG_SRC}/lpeg.a")


set(DIGWATCH_LUA_MAIN "rule_loader.lua")
configure_file(config_digwatch.h.in config_digwatch.h)

install(TARGETS digwatch DESTINATION bin)
install(FILES lua/compiler.lua
	DESTINATION share/digwatch/lua)
install(FILES lua/rule_loader.lua
	DESTINATION share/digwatch/lua)
install(FILES lua/output.lua
	DESTINATION share/digwatch/lua)
